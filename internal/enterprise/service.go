package enterprise

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/stepup"
	"github.com/plystra/auth/internal/store"
)

const (
	stateLifetime         = 5 * time.Minute
	clientSecretAAD       = "plystra-auth-sso-client-secret-v1"
	pkceVerifierAAD       = "plystra-auth-sso-pkce-verifier-v1"
	defaultGroupsClaim    = "groups"
	maxRoleMappings       = 100
	maxIdentityGroups     = 200
	maxExternalSubjectLen = 512
)

type Service struct {
	Store         *store.Store
	Authorization *authorization.Service
	Sessions      *session.Service
	StepUp        stepup.Consumer
	DataKey       secret.String
	Passwords     security.PasswordHasher
	HTTPClient    *http.Client
}

type ConnectionInput struct {
	Name         string
	Provider     string
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	GroupsClaim  string
	RoleMappings map[string]string
}

type Connection struct {
	ID           string            `json:"id"`
	SpaceID      string            `json:"space_id"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	Issuer       string            `json:"issuer"`
	ClientID     string            `json:"client_id"`
	RedirectURI  string            `json:"redirect_uri"`
	GroupsClaim  string            `json:"groups_claim"`
	RoleMappings map[string]string `json:"role_mappings"`
	Status       string            `json:"status"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

type StartResult struct {
	AuthorizationURL string    `json:"authorization_url"`
	State            string    `json:"state"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type CallbackInput struct {
	ConnectionID string
	State        string
	Code         string
	RedirectURI  string
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type idTokenClaims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Nonce         string   `json:"nonce"`
	Groups        []string `json:"groups"`
}

func (s *Service) CreateConnection(ctx context.Context, actorMemberID, spaceID string, in ConnectionInput) (Connection, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.TrimSpace(strings.ToLower(in.Provider))
	in.Issuer = strings.TrimSpace(in.Issuer)
	in.ClientID = strings.TrimSpace(in.ClientID)
	in.RedirectURI = strings.TrimSpace(in.RedirectURI)
	in.GroupsClaim = strings.TrimSpace(in.GroupsClaim)
	if in.GroupsClaim == "" {
		in.GroupsClaim = defaultGroupsClaim
	}
	if in.Name == "" || len(in.Name) > 128 || in.Provider != "oidc" || in.ClientID == "" || len(in.ClientID) > 512 || in.ClientSecret == "" || len(in.ClientSecret) > 4096 || len(in.GroupsClaim) > 128 {
		return Connection{}, apierr.New("validation_failed", "OIDC connection fields are invalid")
	}
	if err := validateIssuer(in.Issuer); err != nil {
		return Connection{}, err
	}
	connectionID := string(ids.New[ids.ID]("con"))
	if strings.Count(in.RedirectURI, "{connection_id}") > 1 || (strings.Contains(in.RedirectURI, "{") && !strings.Contains(in.RedirectURI, "{connection_id}")) || strings.Contains(in.RedirectURI, "}") && !strings.Contains(in.RedirectURI, "{connection_id}") {
		return Connection{}, apierr.New("validation_failed", "redirect_uri contains an unsupported placeholder")
	}
	redirectURI := strings.ReplaceAll(in.RedirectURI, "{connection_id}", connectionID)
	if err := validateRedirectURI(redirectURI); err != nil {
		return Connection{}, err
	}
	if len(in.RoleMappings) > maxRoleMappings {
		return Connection{}, apierr.New("validation_failed", "too many OIDC role mappings")
	}
	for group, roleID := range in.RoleMappings {
		if strings.TrimSpace(group) == "" || len(group) > 256 || strings.TrimSpace(roleID) == "" {
			return Connection{}, apierr.New("validation_failed", "OIDC role mappings are invalid")
		}
	}
	ciphertext, err := s.seal([]byte(in.ClientSecret), clientSecretAAD)
	if err != nil {
		return Connection{}, err
	}
	roleMappings := in.RoleMappings
	if roleMappings == nil {
		roleMappings = map[string]string{}
	}
	mappings, err := json.Marshal(roleMappings)
	if err != nil {
		return Connection{}, err
	}
	var out Connection
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		if s.Authorization == nil {
			return apierr.New("unavailable", "authorization is unavailable")
		}
		decision, err := s.Authorization.CheckMutationTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.connections:manage", ResourceSpace: spaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		if _, err := q.GetSpace(ctx, db.GetSpaceParams{ID: spaceID}); err != nil {
			return err
		}
		for _, roleID := range uniqueRoleIDs(in.RoleMappings) {
			if _, err := q.GetRoleInSpace(ctx, db.GetRoleInSpaceParams{ID: roleID, SpaceID: spaceID}); errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("validation_failed", "role mapping references a role outside this Space")
			} else if err != nil {
				return err
			}
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("unavailable", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		row, err := q.CreateSSOConnection(ctx, db.CreateSSOConnectionParams{
			ID: connectionID, SpaceID: spaceID, Name: in.Name, Provider: in.Provider,
			Issuer: in.Issuer, ClientID: in.ClientID, ClientSecretCiphertext: ciphertext,
			RedirectUri: redirectURI, GroupsClaim: in.GroupsClaim, RoleMappings: mappings,
		})
		if err != nil {
			return err
		}
		out = connectionFromRow(row)
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.connection.create", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_connection", ID: out.ID, SpaceID: spaceID},
			Metadata: map[string]string{"provider": out.Provider, "issuer": out.Issuer},
		})
	})
	if err != nil {
		return Connection{}, normalizeConnectionError(err)
	}
	return out, nil
}

func (s *Service) ListConnections(ctx context.Context, actorMemberID, spaceID string) ([]Connection, error) {
	if s.Authorization == nil {
		return nil, apierr.New("unavailable", "authorization is unavailable")
	}
	var rows []db.ListSSOConnectionsRow
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		decision, err := s.Authorization.CheckMutationTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.connections:manage", ResourceSpace: spaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		rows, err = q.ListSSOConnections(ctx, db.ListSSOConnectionsParams{SpaceID: spaceID})
		return err
	})
	if err != nil {
		return nil, normalizeConnectionError(err)
	}
	out := make([]Connection, 0, len(rows))
	for _, row := range rows {
		out = append(out, connectionFromListRow(row))
	}
	return out, nil
}

func (s *Service) DisableConnection(ctx context.Context, actorMemberID, spaceID, connectionID string) error {
	return normalizeConnectionError(s.Store.InTx(ctx, func(q *db.Queries) error {
		if s.Authorization == nil {
			return apierr.New("unavailable", "authorization is unavailable")
		}
		decision, err := s.Authorization.CheckMutationTx(ctx, q, authorization.CheckRequest{
			MemberID: actorMemberID, Permission: "auth.connections:manage", ResourceSpace: spaceID,
		})
		if err != nil {
			return err
		}
		if decision.Effect != engine.Allow {
			return &apierr.Error{Code: decision.Code, Message: "The authorization engine denied this operation."}
		}
		connection, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: connectionID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("not_found", "SSO connection was not found")
		}
		if err != nil {
			return err
		}
		if connection.SpaceID != spaceID {
			return apierr.New("not_found", "SSO connection was not found")
		}
		if _, required := stepup.RequirementFromContext(ctx); required {
			if s.StepUp == nil {
				return apierr.New("unavailable", "step-up authentication is unavailable")
			}
			if err := s.StepUp.ConsumeStepUpTx(ctx, q); err != nil {
				return err
			}
		}
		if err := q.DisableSSOConnection(ctx, db.DisableSSOConnectionParams{ID: connection.ID}); err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "member", ActorID: actorMemberID, MemberID: actorMemberID,
			Action: "sso.connection.disable", Outcome: "success", Permission: "auth.connections:manage",
			Resource: audit.Resource{Type: "sso_connection", ID: connection.ID, SpaceID: spaceID},
		})
	}))
}

func (s *Service) Start(ctx context.Context, connectionID, requestedRedirectURI string) (StartResult, error) {
	connectionID = strings.TrimSpace(connectionID)
	row, err := s.Store.Queries().GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: connectionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return StartResult{}, apierr.New("not_found", "SSO connection was not found")
	}
	if err != nil {
		return StartResult{}, err
	}
	if row.Status != "active" {
		return StartResult{}, apierr.New("forbidden", "SSO connection is disabled")
	}
	redirectURI := strings.TrimSpace(requestedRedirectURI)
	if redirectURI == "" {
		redirectURI = row.RedirectUri
	}
	if redirectURI != row.RedirectUri {
		return StartResult{}, apierr.New("invalid_request", "redirect_uri does not match the configured connection")
	}
	doc, _, err := s.discovery(ctx, row.Issuer)
	if err != nil {
		return StartResult{}, err
	}
	state, err := randomOpaque("sso_state_")
	if err != nil {
		return StartResult{}, err
	}
	nonce, err := randomOpaque("sso_nonce_")
	if err != nil {
		return StartResult{}, err
	}
	verifier, err := randomOpaque("")
	if err != nil {
		return StartResult{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	expiresAt := time.Now().UTC().Add(stateLifetime)
	verifierCiphertext, err := s.seal([]byte(verifier), pkceVerifierAAD)
	if err != nil {
		return StartResult{}, err
	}
	if err := s.Store.InTx(ctx, func(q *db.Queries) error {
		_, err := q.CreateSSOState(ctx, db.CreateSSOStateParams{
			ID: string(ids.New[ids.ID]("sos")), ConnectionID: row.ID,
			StateHash: digest(state), NonceHash: digest(nonce),
			PkceVerifierCiphertext: verifierCiphertext, RedirectUri: redirectURI,
			ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		})
		return err
	}); err != nil {
		return StartResult{}, err
	}
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", row.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("scope", "openid email profile")
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("code_challenge_method", "S256")
	return StartResult{AuthorizationURL: doc.AuthorizationEndpoint + "?" + query.Encode(), State: state, ExpiresAt: expiresAt}, nil
}

func (s *Service) Callback(ctx context.Context, in CallbackInput) (account.AuthResult, error) {
	in.ConnectionID = strings.TrimSpace(in.ConnectionID)
	in.State = strings.TrimSpace(in.State)
	in.Code = strings.TrimSpace(in.Code)
	in.RedirectURI = strings.TrimSpace(in.RedirectURI)
	if in.ConnectionID == "" || in.State == "" || in.Code == "" {
		return account.AuthResult{}, apierr.New("invalid_request", "connection_id, state and code are required")
	}
	row, err := s.Store.Queries().GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: in.ConnectionID})
	if errors.Is(err, pgx.ErrNoRows) {
		return account.AuthResult{}, apierr.New("invalid_grant", "SSO state is invalid or expired")
	}
	if err != nil {
		return account.AuthResult{}, err
	}
	if row.Status != "active" {
		return account.AuthResult{}, apierr.New("forbidden", "SSO connection is disabled")
	}
	var state db.SsoState
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		state, err = q.LockSSOStateByHash(ctx, db.LockSSOStateByHashParams{StateHash: digest(in.State)})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "SSO state is invalid or expired")
		}
		if err != nil {
			return err
		}
		if state.ConnectionID != row.ID || state.ConsumedAt.Valid || !state.ExpiresAt.Time.After(time.Now().UTC()) {
			return apierr.New("invalid_grant", "SSO state is invalid or expired")
		}
		if in.RedirectURI != "" && in.RedirectURI != state.RedirectUri {
			return apierr.New("invalid_grant", "redirect_uri does not match the SSO request")
		}
		return nil
	})
	if err != nil {
		return account.AuthResult{}, err
	}
	verifier, err := s.open(state.PkceVerifierCiphertext, pkceVerifierAAD)
	if err != nil {
		return account.AuthResult{}, apierr.New("temporarily_unavailable", "SSO state is unavailable")
	}
	doc, provider, err := s.discovery(ctx, row.Issuer)
	if err != nil {
		return account.AuthResult{}, err
	}
	clientSecret, err := s.open(row.ClientSecretCiphertext, clientSecretAAD)
	if err != nil {
		return account.AuthResult{}, apierr.New("temporarily_unavailable", "SSO connection is unavailable")
	}
	config := oauth2.Config{ClientID: row.ClientID, ClientSecret: string(clientSecret), Endpoint: provider.Endpoint(), RedirectURL: state.RedirectUri, Scopes: []string{"openid", "email", "profile"}}
	exchangeCtx := context.WithValue(ctx, oauth2.HTTPClient, s.httpClient())
	token, err := config.Exchange(exchangeCtx, in.Code, oauth2.SetAuthURLParam("code_verifier", string(verifier)))
	if err != nil {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC authorization code is invalid")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC provider did not return an ID token")
	}
	claims, err := parseIDToken(exchangeCtx, provider, rawIDToken, row.ClientID, row.GroupsClaim)
	if err != nil {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC ID token is invalid")
	}
	if claims.Nonce == "" || !equalDigest(state.NonceHash, claims.Nonce) || claims.Subject == "" || len(claims.Subject) > maxExternalSubjectLen || claims.Email == "" || !claims.EmailVerified {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC identity is not valid for this connection")
	}
	if err := validateIssuer(doc.Issuer); err != nil || doc.Issuer != row.Issuer {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC issuer is invalid")
	}
	result, err := s.finishCallback(ctx, row, state, claims)
	if err != nil {
		return account.AuthResult{}, err
	}
	return result, nil
}

func (s *Service) finishCallback(ctx context.Context, connection db.SsoConnection, state db.SsoState, claims idTokenClaims) (account.AuthResult, error) {
	email := strings.TrimSpace(strings.ToLower(claims.Email))
	if email == "" || len(email) > 320 || strings.ContainsAny(email, "\r\n") {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC email claim is invalid")
	}
	groups := claims.Groups
	if len(groups) > maxIdentityGroups {
		return account.AuthResult{}, apierr.New("invalid_grant", "the OIDC groups claim is too large")
	}
	var userID, memberID string
	var userEmail, userStatus string
	var userCreated time.Time
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		lockedConnection, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: connection.ID})
		if err != nil {
			return err
		}
		if lockedConnection.Status != "active" {
			return apierr.New("forbidden", "SSO connection is disabled")
		}
		lockedState, err := q.LockSSOStateByHash(ctx, db.LockSSOStateByHashParams{StateHash: state.StateHash})
		if err != nil {
			return err
		}
		if lockedState.ConsumedAt.Valid || !lockedState.ExpiresAt.Time.After(time.Now().UTC()) || lockedState.ConnectionID != connection.ID {
			return apierr.New("invalid_grant", "SSO state is invalid or expired")
		}
		if err := q.ConsumeSSOState(ctx, db.ConsumeSSOStateParams{ID: lockedState.ID}); err != nil {
			return err
		}
		external, err := q.GetExternalIdentity(ctx, db.GetExternalIdentityParams{Issuer: connection.Issuer, Subject: claims.Subject})
		newMembership := false
		if errors.Is(err, pgx.ErrNoRows) {
			if existing, emailErr := q.GetUserByEmail(ctx, db.GetUserByEmailParams{EmailNormalized: email}); emailErr == nil {
				_ = existing
				return apierr.New("conflict", "an account with this email requires explicit SSO identity linking")
			} else if !errors.Is(emailErr, pgx.ErrNoRows) {
				return emailErr
			}
			passwordHash, hashErr := s.passwordHash()
			if hashErr != nil {
				return hashErr
			}
			created, createErr := q.CreateUser(ctx, db.CreateUserParams{ID: string(ids.New[ids.UserID]("usr")), Email: email, EmailNormalized: email, PasswordHash: passwordHash, Status: "active"})
			if createErr != nil {
				return createErr
			}
			userID, userEmail, userStatus, userCreated = created.ID, created.Email, created.Status, created.CreatedAt.Time
			if err := q.MarkExternalUserVerified(ctx, db.MarkExternalUserVerifiedParams{ID: userID}); err != nil {
				return err
			}
			if _, err := q.CreateExternalIdentity(ctx, db.CreateExternalIdentityParams{ID: string(ids.New[ids.ID]("ext")), UserID: userID, Issuer: connection.Issuer, Subject: claims.Subject}); err != nil {
				return err
			}
			newMembership = true
		} else if err != nil {
			return err
		} else {
			userID = external.UserID
			user, userErr := q.GetUserByID(ctx, db.GetUserByIDParams{ID: userID})
			if userErr != nil {
				return userErr
			}
			if user.Status != "active" {
				return apierr.New("forbidden", "the linked account is not active")
			}
			userEmail, userStatus, userCreated = user.Email, user.Status, user.CreatedAt.Time
		}
		member, memberErr := q.GetMemberForUser(ctx, db.GetMemberForUserParams{UserID: userID, SpaceID: connection.SpaceID})
		if errors.Is(memberErr, pgx.ErrNoRows) {
			createdMember, createErr := q.CreateMemberWithPolicy(ctx, db.CreateMemberWithPolicyParams{ID: string(ids.New[ids.MemberID]("mem")), SpaceID: connection.SpaceID, Name: displayName(claims, email), Type: "human", BindingPolicy: "single"})
			if createErr != nil {
				return createErr
			}
			memberID = createdMember.ID
			if err := q.LinkUserMember(ctx, db.LinkUserMemberParams{UserID: userID, MemberID: memberID}); err != nil {
				return err
			}
			newMembership = true
		} else if memberErr != nil {
			return memberErr
		} else {
			memberID = member.ID
		}
		if newMembership {
			roles, err := s.rolesForLogin(ctx, q, connection, groups)
			if err != nil {
				return err
			}
			for _, roleID := range roles {
				if _, err := q.CreateGrant(ctx, db.CreateGrantParams{
					ID: string(ids.New[ids.GrantID]("grt")), SpaceID: connection.SpaceID,
					RoleID: pgtype.Text{String: roleID, Valid: true}, GranteeMemberID: pgtype.Text{String: memberID, Valid: true},
					Scope: "space", AnchorSpaceID: pgtype.Text{String: connection.SpaceID, Valid: true}, GrantedBy: connection.ID,
				}); err != nil {
					return err
				}
			}
		}
		space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: connection.SpaceID})
		if err != nil {
			return err
		}
		return audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "sso", ActorID: connection.ID, MemberID: memberID, UserID: userID,
			Action: "auth.sso.login", Outcome: "success", CredentialType: "oidc",
			Resource:      audit.Resource{Type: "sso_connection", ID: connection.ID, SpaceID: connection.SpaceID},
			PolicyVersion: space.PolicyVersion,
			Metadata:      map[string]string{"provider": connection.Provider, "subject_hash": hexDigest(claims.Subject), "new_membership": fmt.Sprintf("%t", newMembership)},
		})
	})
	if err != nil {
		return account.AuthResult{}, normalizeConnectionError(err)
	}
	if s.Sessions == nil {
		return account.AuthResult{}, apierr.New("unavailable", "session service is unavailable")
	}
	tokens, err := s.Sessions.CreateForMemberWithMethods(ctx, userID, memberID, nil, "", 1, []string{"oidc"})
	if err != nil {
		return account.AuthResult{}, err
	}
	return account.AuthResult{User: account.User{ID: userID, Email: userEmail, EmailVerified: true, Status: userStatus, DisplayName: displayName(claims, userEmail), CreatedAt: userCreated}, Tokens: &tokens}, nil
}

func (s *Service) rolesForLogin(ctx context.Context, q *db.Queries, connection db.SsoConnection, groups []string) ([]string, error) {
	defaultRole, err := q.GetRoleByNameInSpace(ctx, db.GetRoleByNameInSpaceParams{SpaceID: connection.SpaceID, Name: "member"})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.New("temporarily_unavailable", "the Space has no default member role")
	}
	if err != nil {
		return nil, err
	}
	var mappings map[string]string
	if err := json.Unmarshal(connection.RoleMappings, &mappings); err != nil {
		return nil, err
	}
	roles := []string{defaultRole.ID}
	seen := map[string]struct{}{defaultRole.ID: {}}
	for _, group := range groups {
		roleID, ok := mappings[group]
		if !ok {
			continue
		}
		if _, ok := seen[roleID]; ok {
			continue
		}
		if _, err := q.GetRoleInSpace(ctx, db.GetRoleInSpaceParams{ID: roleID, SpaceID: connection.SpaceID}); errors.Is(err, pgx.ErrNoRows) {
			return nil, apierr.New("temporarily_unavailable", "an SSO role mapping references a missing role")
		} else if err != nil {
			return nil, err
		}
		seen[roleID] = struct{}{}
		roles = append(roles, roleID)
	}
	return roles, nil
}

func (s *Service) discovery(ctx context.Context, issuer string) (discoveryDocument, *oidc.Provider, error) {
	if err := validateIssuer(issuer); err != nil {
		return discoveryDocument{}, nil, err
	}
	client := s.httpClient()
	requestCtx := context.WithValue(ctx, oauth2.HTTPClient, client)
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return discoveryDocument{}, nil, apierr.New("temporarily_unavailable", "OIDC discovery is unavailable")
	}
	resp, err := client.Do(req)
	if err != nil {
		return discoveryDocument{}, nil, apierr.New("temporarily_unavailable", "OIDC discovery is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return discoveryDocument{}, nil, apierr.New("temporarily_unavailable", "OIDC discovery is unavailable")
	}
	var doc discoveryDocument
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&doc); err != nil {
		return discoveryDocument{}, nil, apierr.New("temporarily_unavailable", "OIDC discovery is invalid")
	}
	if doc.Issuer != issuer || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return discoveryDocument{}, nil, apierr.New("temporarily_unavailable", "OIDC discovery is invalid")
	}
	for _, endpoint := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
		if err := validateEndpoint(endpoint, issuer); err != nil {
			return discoveryDocument{}, nil, apierr.New("temporarily_unavailable", "OIDC discovery contains an unsafe endpoint")
		}
	}
	provider, err := oidc.NewProvider(requestCtx, issuer)
	if err != nil {
		return discoveryDocument{}, nil, apierr.New("temporarily_unavailable", "OIDC provider discovery is unavailable")
	}
	return doc, provider, nil
}

func parseIDToken(ctx context.Context, provider *oidc.Provider, raw, clientID, groupsClaim string) (idTokenClaims, error) {
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	token, err := verifier.Verify(ctx, raw)
	if err != nil {
		return idTokenClaims{}, err
	}
	var claims idTokenClaims
	if err := token.Claims(&claims); err != nil {
		return idTokenClaims{}, err
	}
	if groupsClaim != "" && groupsClaim != "groups" {
		var rawClaims map[string]json.RawMessage
		if err := token.Claims(&rawClaims); err != nil {
			return idTokenClaims{}, err
		}
		if value, ok := rawClaims[groupsClaim]; ok {
			if err := json.Unmarshal(value, &claims.Groups); err != nil {
				return idTokenClaims{}, err
			}
		}
	}
	return claims, nil
}

func (s *Service) passwordHash() (string, error) {
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return "", err
	}
	hasher := s.Passwords
	if hasher.Time == 0 {
		hasher = security.DefaultPasswordHasher()
	}
	return hasher.Hash(base64.RawURLEncoding.EncodeToString(password))
}

func (s *Service) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

func (s *Service) seal(plain []byte, aad string) ([]byte, error) {
	aead, err := s.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

func (s *Service) open(ciphertext []byte, aad string) ([]byte, error) {
	aead, err := s.aead()
	if err != nil || len(ciphertext) < aead.NonceSize() {
		if err == nil {
			err = errors.New("ciphertext is too short")
		}
		return nil, err
	}
	return aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], []byte(aad))
}

func (s *Service) aead() (cipher.AEAD, error) {
	key := []byte(s.DataKey.Value())
	if len(key) != 32 {
		return nil, errors.New("enterprise data key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomOpaque(prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func equalDigest(expected []byte, value string) bool {
	actual := digest(value)
	return len(expected) == len(actual) && subtleCompare(expected, actual)
}

func subtleCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func hexDigest(value string) string {
	sum := digest(value)
	return fmt.Sprintf("%x", sum)
}

func validateIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost")) {
		return apierr.New("validation_failed", "issuer must be an HTTPS URL without user info, query, or fragment")
	}
	return nil
}

func validateEndpoint(raw, issuer string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost")) {
		return errors.New("unsafe OIDC endpoint")
	}
	base, err := url.Parse(issuer)
	if err != nil || u.Scheme != base.Scheme || !strings.EqualFold(u.Hostname(), base.Hostname()) || u.Port() != base.Port() {
		return errors.New("OIDC endpoint origin differs from issuer")
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, "*\r\n\t ") {
		return apierr.New("validation_failed", "redirect_uri must be an exact URL without wildcards")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost") {
		return apierr.New("validation_failed", "redirect_uri must use HTTPS")
	}
	return nil
}

func displayName(claims idTokenClaims, email string) string {
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = strings.TrimSpace(strings.SplitN(email, "@", 2)[0])
	}
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

func uniqueRoleIDs(mappings map[string]string) []string {
	seen := make(map[string]struct{}, len(mappings))
	roles := make([]string, 0, len(mappings))
	for _, roleID := range mappings {
		if _, ok := seen[roleID]; ok {
			continue
		}
		seen[roleID] = struct{}{}
		roles = append(roles, roleID)
	}
	return roles
}

func connectionFromRow(row db.CreateSSOConnectionRow) Connection {
	return connectionFromValues(row.ID, row.SpaceID, row.Name, row.Provider, row.Issuer, row.ClientID, row.RedirectUri, row.GroupsClaim, row.RoleMappings, row.Status, row.CreatedAt.Time, row.UpdatedAt.Time)
}

func connectionFromListRow(row db.ListSSOConnectionsRow) Connection {
	return connectionFromValues(row.ID, row.SpaceID, row.Name, row.Provider, row.Issuer, row.ClientID, row.RedirectUri, row.GroupsClaim, row.RoleMappings, row.Status, row.CreatedAt.Time, row.UpdatedAt.Time)
}

func connectionFromValues(id, spaceID, name, provider, issuer, clientID, redirectURI, groupsClaim string, rawMappings []byte, status string, createdAt, updatedAt time.Time) Connection {
	mappings := map[string]string{}
	_ = json.Unmarshal(rawMappings, &mappings)
	return Connection{ID: id, SpaceID: spaceID, Name: name, Provider: provider, Issuer: issuer, ClientID: clientID, RedirectURI: redirectURI, GroupsClaim: groupsClaim, RoleMappings: mappings, Status: status, CreatedAt: createdAt, UpdatedAt: updatedAt}
}

func normalizeConnectionError(err error) error {
	if err == nil {
		return nil
	}
	var public *apierr.Error
	if errors.As(err, &public) {
		return public
	}
	if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
		return apierr.New("conflict", "an SSO connection or identity already exists")
	}
	return err
}
