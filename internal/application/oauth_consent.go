package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/session"
)

type OAuthConsentInput struct {
	RequestID   secret.String
	AccessToken secret.String
	UserID      string
	Decision    string
	MemberID    string
	Permissions []string
}

type OAuthConsent struct {
	Applications  *Service
	Agents        *agent.Service
	Authorization *authorization.Service
	Sessions      *session.Service
}

// Decide locks and consumes a consent request in the same transaction as the
// Agent, its grant, the authorization code, and the audit record.
func (s OAuthConsent) Decide(ctx context.Context, in OAuthConsentInput) (string, error) {
	if s.Applications == nil || s.Applications.Store == nil || s.Agents == nil || s.Authorization == nil || s.Sessions == nil {
		return "", apierr.New("temporarily_unavailable", "authorization is unavailable")
	}
	if in.UserID == "" || (in.Decision != "approve" && in.Decision != "deny") {
		return "", apierr.New("invalid_request", "authorization decision is invalid")
	}
	if in.Decision == "approve" && (in.MemberID == "" || len(in.Permissions) == 0 || len(in.Permissions) > 100) {
		return "", apierr.New("invalid_request", "member_id and permissions are required for approval")
	}
	if in.Decision == "deny" && (in.MemberID != "" || len(in.Permissions) != 0) {
		return "", apierr.New("invalid_request", "denial must not select a member or permissions")
	}
	claims, err := s.Sessions.VerifyAccess(in.AccessToken.Value())
	if err != nil || claims.Type != "user" || claims.Subject != in.UserID || claims.SessionID == "" {
		return "", apierr.New("invalid_token", "an authenticated user session is required")
	}
	permissions := uniqueConsentPermissions(in.Permissions)
	if in.Decision == "approve" && len(permissions) != len(in.Permissions) {
		return "", apierr.New("invalid_scope", "permissions contain duplicates or empty values")
	}
	var code secret.String
	var codeHash []byte
	if in.Decision == "approve" {
		var err error
		code, codeHash, err = newOAuthAuthorizationCode()
		if err != nil {
			return "", err
		}
	}
	var redirectTo string
	err = s.Applications.Store.InTx(ctx, func(q *db.Queries) error {
		request, err := s.Applications.LockOAuthAuthorizationRequestTx(ctx, q, in.RequestID)
		if err != nil {
			return err
		}
		client, err := s.Applications.OAuthClientByIDTx(ctx, q, request.ApplicationID)
		if err != nil {
			return err
		}
		user, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: in.UserID})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && user.Status != "active" {
			return apierr.New("invalid_token", "an active user account is required")
		}
		if err != nil {
			return err
		}
		// Binding revocation locks members before sessions. Keep that order for
		// the bearer member as well as a separately selected consent member.
		if err := member.LockChainsTx(ctx, q, claims.MemberID, in.MemberID); err != nil {
			return err
		}
		if _, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: claims.SessionID}); errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_token", "an authenticated user session is required")
		} else if err != nil {
			return err
		}
		validateSession := func(spaceID string) error {
			currentClaims, active, err := s.Sessions.IntrospectForSpaceTx(ctx, q, in.AccessToken.Value(), claims.Audience, spaceID)
			if err != nil {
				return err
			}
			if !active || currentClaims.Type != "user" || currentClaims.Subject != in.UserID {
				return apierr.New("invalid_token", "an authenticated user session is required")
			}
			return nil
		}
		if err := validateSession(""); err != nil {
			return err
		}
		if !slices.Contains(client.RedirectURIs, request.RedirectURI) {
			return apierr.New("invalid_request", "redirect_uri is no longer registered for this client")
		}
		if request.Resource != client.ClientID {
			return apierr.New("invalid_target", "resource is no longer registered for this client")
		}
		redirect, err := url.Parse(request.RedirectURI)
		if err != nil {
			return apierr.New("invalid_request", "redirect_uri is invalid")
		}
		query := redirect.Query()
		query.Del("code")
		query.Del("error")
		query.Set("state", request.State)
		if in.Decision == "deny" {
			query.Set("error", "access_denied")
			publisher, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: client.SpaceID})
			if err != nil {
				return err
			}
			if err := validateSession(""); err != nil {
				return err
			}
			if err := s.Applications.FinishOAuthAuthorizationRequestTx(ctx, q, request.ID, "denied"); err != nil {
				return err
			}
			if err := audit.WriteAccountEvent(ctx, q, audit.SecurityEvent{
				ActorType: "user", ActorID: in.UserID, UserID: in.UserID, ApplicationID: client.ID,
				Action: "oauth.consent.deny", Outcome: "success", CredentialType: "user_access_token", PolicyVersion: publisher.PolicyVersion,
				Resource: audit.Resource{Type: "application", ID: client.ID, SpaceID: client.SpaceID},
				Metadata: map[string]string{"authorization_request_id": request.ID, "subject_selection": "none"},
			}); err != nil {
				return err
			}
			redirect.RawQuery = query.Encode()
			redirectTo = redirect.String()
			return nil
		}
		for _, permission := range permissions {
			if !slices.Contains(request.Scopes, permission) || !slices.Contains(client.AllowedScopes, permission) {
				return apierr.New("invalid_scope", "permission is outside the authorization request or client manifest")
			}
		}
		memberRef, err := q.GetMemberForAuthorization(ctx, db.GetMemberForAuthorizationParams{ID: in.MemberID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_request", "member_id is not bound to the authenticated user")
		}
		if err != nil {
			return err
		}
		member, err := q.LockMemberInSpace(ctx, db.LockMemberInSpaceParams{ID: in.MemberID, SpaceID: memberRef.SpaceID})
		if err != nil {
			return err
		}
		if member.Type != "human" || member.Status != "active" {
			return apierr.New("invalid_request", "member_id must identify an active human member")
		}
		binding, err := q.LockUserMemberBinding(ctx, db.LockUserMemberBindingParams{UserID: in.UserID, MemberID: member.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_request", "member_id is not bound to the authenticated user")
		}
		if err != nil {
			return err
		}
		if binding.Status != "active" || binding.RevokedAt.Valid || (binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(time.Now().UTC())) {
			return apierr.New("invalid_request", "member_id is not bound to the authenticated user")
		}
		if err := validateSession(member.SpaceID); err != nil {
			return err
		}
		installation, err := q.LockActiveApplicationInstallationForSpace(ctx, db.LockActiveApplicationInstallationForSpaceParams{
			ApplicationID: client.ID, TargetSpaceID: member.SpaceID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_request", "application is not installed in the selected member's Space")
		}
		if err != nil {
			return err
		}
		var approved []string
		if err := json.Unmarshal(installation.ApprovedPermissions, &approved); err != nil {
			return apierr.New("temporarily_unavailable", "application installation is invalid")
		}
		for _, permission := range permissions {
			if !slices.Contains(approved, permission) {
				return apierr.New("invalid_scope", "application installation has not approved the requested permission")
			}
		}
		if err := s.Authorization.ValidateOAuthGrantTx(ctx, q, member.ID, member.SpaceID, permissions); err != nil {
			return err
		}
		ctx = audit.WithCaller(ctx, audit.Caller{UserID: in.UserID, ApplicationID: client.ID, CredentialType: "user_access_token"})
		current, err := s.Agents.OAuthAgentTx(ctx, q, member.ID, client.ClientID)
		if err != nil {
			var public *apierr.Error
			if !errors.As(err, &public) || public.Code != "NOT_FOUND" {
				return err
			}
			name := strings.TrimSpace(client.Name + " OAuth Agent")
			if len([]rune(name)) > 128 {
				name = string([]rune(name)[:128])
			}
			current, err = s.Agents.CreateOAuthTx(ctx, q, agent.CreateInput{
				OwnerMemberID: member.ID, CreatedByUser: in.UserID, Name: name,
				Source: "oauth", OAuthClientID: client.ClientID, ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
			})
			if err != nil {
				return err
			}
			if _, err := s.Authorization.CreateOAuthInlineGrantTx(ctx, q, member.ID, member.SpaceID, current.ID, permissions); err != nil {
				return err
			}
		} else {
			if current.Status != "active" {
				return apierr.New("invalid_request", "the existing OAuth Agent is not active")
			}
			renewed, err := q.RenewOAuthAgent(ctx, db.RenewOAuthAgentParams{
				MemberID: current.ID, OwnerMemberID: pgtype.Text{String: member.ID, Valid: true},
				OauthClientID: pgtype.Text{String: client.ClientID, Valid: true},
				ExpiresAt:     pgtype.Timestamptz{Time: time.Now().UTC().Add(30 * 24 * time.Hour), Valid: true},
			})
			if err != nil {
				return err
			}
			if renewed != 1 {
				return apierr.New("invalid_request", "the existing OAuth Agent is not active")
			}
			if _, err := s.Authorization.ReplaceOAuthInlineGrantsTx(ctx, q, member.ID, member.SpaceID, current.ID, permissions); err != nil {
				return err
			}
		}
		if err := s.Applications.CreateAuthorizationCodeTx(ctx, q, CreateAuthorizationCodeInput{
			ID: string(ids.New[ids.ID]("cod")), ApplicationID: client.ID, UserID: in.UserID, MemberID: current.ID,
			RedirectURI: request.RedirectURI, CodeHash: codeHash, CodeChallenge: request.CodeChallenge,
			CodeChallengeMethod: "S256", Scope: strings.Join(permissions, " "), Nonce: request.Nonce,
			Resource: request.Resource, ExpiresAt: time.Now().UTC().Add(time.Minute),
		}); err != nil {
			return err
		}
		// Time-based identity validity can change while waiting for resource
		// locks even though account, member, binding, and session rows are held.
		if err := validateSession(member.SpaceID); err != nil {
			return err
		}
		if binding.ExpiresAt.Valid && !binding.ExpiresAt.Time.After(time.Now().UTC()) {
			return apierr.New("invalid_request", "member_id is not bound to the authenticated user")
		}
		if err := s.Applications.FinishOAuthAuthorizationRequestTx(ctx, q, request.ID, "approved"); err != nil {
			return err
		}
		space, err := q.GetSpace(ctx, db.GetSpaceParams{ID: member.SpaceID})
		if err != nil {
			return err
		}
		if err := audit.WriteSecurityEvent(ctx, q, audit.SecurityEvent{
			ActorType: "user", ActorID: in.UserID, Action: "oauth.consent.approve", Outcome: "success", MemberID: current.ID,
			PolicyVersion: space.PolicyVersion,
			Metadata:      map[string]string{"authorization_request_id": request.ID, "owner_member_id": member.ID},
		}); err != nil {
			return err
		}
		query.Set("code", code.Value())
		redirect.RawQuery = query.Encode()
		redirectTo = redirect.String()
		return nil
	})
	return redirectTo, err
}

func uniqueConsentPermissions(input []string) []string {
	out := make([]string, 0, len(input))
	for _, permission := range input {
		if permission != "" && strings.TrimSpace(permission) == permission && !slices.Contains(out, permission) {
			out = append(out, permission)
		}
	}
	return out
}

func newOAuthAuthorizationCode() (secret.String, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	code := secret.New("ply_ac_" + base64.RawURLEncoding.EncodeToString(raw))
	hash := sha256.Sum256([]byte(code.Value()))
	return code, hash[:], nil
}
