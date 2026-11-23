package protocol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
)

type tokenService struct {
	applications  *application.Service
	agents        *agent.Service
	sessions      *session.Service
	authorization *authorization.Service
}

func (s tokenService) agentKey(ctx context.Context, raw secret.String, resource string) (session.Tokens, error) {
	var tokens session.Tokens
	err := s.agents.Store.InTx(ctx, func(q *db.Queries) error {
		credential, err := s.agents.AuthenticateKeyTx(ctx, q, raw.Value())
		if err != nil {
			return exchangeCredentialError(err)
		}
		ctx = audit.WithCaller(ctx, audit.Caller{CredentialType: "agent_key"})
		tokens, err = s.sessions.CreateAgentAccessTx(ctx, q, credential.MemberID, credential.SpaceID, resource)
		return err
	})
	if err != nil {
		return session.Tokens{}, err
	}
	return tokens, nil
}

func (s tokenService) delegated(ctx context.Context, subject, actor secret.String, requested []string, resource string) (session.Tokens, string, error) {
	resource = strings.TrimSpace(resource)
	var tokens session.Tokens
	var scope string
	err := s.agents.Store.InTx(ctx, func(q *db.Queries) error {
		signer, err := s.sessions.CurrentSigner(ctx, q)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		verified, err := signer.Verify(subject.Value(), now, security.DefaultApplicationAudience)
		if err != nil && resource != "" && resource != security.DefaultApplicationAudience {
			verified, err = signer.Verify(subject.Value(), now, resource)
		}
		if err != nil || verified.Type != "agent" {
			return apierr.New("invalid_grant", "subject token is invalid")
		}
		var client application.OAuthClient
		if verified.Audience != security.DefaultApplicationAudience {
			if s.applications == nil {
				return apierr.New("temporarily_unavailable", "application token exchange is unavailable")
			}
			// Application lifecycle and consent take the application lock before
			// any members. Resolve only from the already verified audience.
			ref, err := q.GetApplicationByClientID(ctx, db.GetApplicationByClientIDParams{ClientID: verified.Audience})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.New("invalid_grant", "subject application is unavailable")
			}
			if err != nil {
				return err
			}
			client, err = s.applications.OAuthClientByIDTx(ctx, q, ref.ID)
			if err != nil {
				var public *apierr.Error
				if errors.As(err, &public) && public.Code == "invalid_request" {
					return apierr.New("invalid_grant", "subject application is unavailable")
				}
				return err
			}
		}
		credential, err := s.agents.AuthenticateKeyTx(ctx, q, actor.Value())
		if err != nil {
			return exchangeCredentialError(err)
		}
		if err := s.agents.ValidateActiveTx(ctx, q, credential.MemberID); err != nil {
			return exchangeCredentialError(err)
		}
		// The authenticated child's persisted owner chain is locked before
		// reading the parent JWT's current revocation epoch and authority.
		parent, active, err := s.sessions.IntrospectTx(ctx, q, subject.Value(), verified.Audience)
		if err != nil {
			return err
		}
		if !active || parent.Type != "agent" {
			return apierr.New("invalid_grant", "subject token is invalid")
		}
		child, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: credential.MemberID})
		if err != nil {
			return err
		}
		if child.OwnerMemberID.String != parent.Subject {
			return apierr.New("invalid_grant", "actor token is not delegated by the subject")
		}
		requested = uniqueScopes(requested)
		if client.ID != "" {
			requested, err = s.oauthScopesTx(ctx, q, parent, credential.SpaceID, credential.MemberID, client, requested, false)
			if err != nil {
				return err
			}
		} else {
			parentScopes := uniqueScopes(parent.Scopes)
			if len(requested) == 0 && len(parentScopes) > 0 {
				requested = parentScopes
			}
			if len(parentScopes) > 0 {
				for _, permission := range requested {
					if !scopeContains(parentScopes, permission) {
						return apierr.New("invalid_scope", "requested scope exceeds the subject token scope")
					}
				}
			}
			allowed, err := s.authorization.ValidateTokenScopesTx(ctx, q, credential.MemberID, requested)
			if err != nil {
				return err
			}
			if !allowed {
				return apierr.New("invalid_scope", "requested scope is not held by the delegated Agent")
			}
		}
		scope = strings.Join(requested, " ")
		ctx = audit.WithCaller(ctx, audit.Caller{ApplicationID: client.ID, CredentialType: "agent_token_exchange"})
		tokens, err = s.sessions.CreateAgentDelegatedAccessTx(ctx, q, credential.MemberID, credential.SpaceID, resource, parent.Subject, requested, parent.ExpiresAt)
		return err
	})
	if err != nil {
		return session.Tokens{}, "", err
	}
	return tokens, scope, nil
}

func (s tokenService) oauthScopesTx(ctx context.Context, q *db.Queries, parent security.Claims, spaceID, memberID string, client application.OAuthClient, requested []string, rootRefresh bool) ([]string, error) {
	member, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: parent.Subject})
	if err != nil {
		return nil, err
	}
	if member.Source.String == "oauth" && member.OauthClientID.String != client.ClientID {
		return nil, apierr.New("invalid_grant", "subject token does not belong to this application")
	}
	installation, err := q.LockActiveApplicationInstallationForSpace(ctx, db.LockActiveApplicationInstallationForSpaceParams{
		ApplicationID: client.ID, TargetSpaceID: spaceID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.New("invalid_grant", "application is not installed")
	}
	if err != nil {
		return nil, err
	}
	var approved []string
	if json.Unmarshal(installation.ApprovedPermissions, &approved) != nil {
		return nil, apierr.New("temporarily_unavailable", "application installation is invalid")
	}
	explicit := len(requested) > 0
	if !explicit {
		requested = uniqueScopes(client.AllowedScopes)
	}
	allowed := make([]string, 0, len(requested))
	for _, permission := range requested {
		usable := scopeContains(client.AllowedScopes, permission) && scopeContains(approved, permission) &&
			(parent.Scopes == nil || scopeContains(parent.Scopes, permission))
		if usable {
			if rootRefresh {
				usable, err = s.authorization.ValidateOAuthTokenScopesTx(ctx, q, memberID, []string{permission})
			} else {
				usable, err = s.authorization.ValidateTokenScopesTx(ctx, q, memberID, []string{permission})
			}
			if err != nil {
				return nil, err
			}
		}
		if !usable {
			if explicit {
				return nil, apierr.New("invalid_scope", "requested scope is outside the application or delegated authority")
			}
			continue
		}
		allowed = append(allowed, permission)
	}
	if len(allowed) == 0 {
		return nil, apierr.New("invalid_scope", "no requested scope is held by the delegated Agent")
	}
	return allowed, nil
}

func exchangeCredentialError(err error) error {
	var public *apierr.Error
	if errors.As(err, &public) && public.Code == "UNAUTHENTICATED" {
		return apierr.New("invalid_grant", "agent credential is invalid")
	}
	return err
}

type codeExchangeInput struct {
	client                clientCredentials
	redirectURI, resource string
	code, verifier        secret.String
}

func (s tokenService) authorizationCode(ctx context.Context, in codeExchangeInput) (session.Tokens, string, error) {
	var tokens session.Tokens
	var scope string
	err := s.applications.Store.InTx(ctx, func(q *db.Queries) error {
		client, err := s.applications.AuthenticateOAuthClientMethodTx(ctx, q, in.client.id, in.client.secret.Value(), in.client.method)
		if err != nil {
			return err
		}
		if !containsString(client.RedirectURIs, in.redirectURI) {
			return apierr.New("invalid_grant", "authorization code is invalid or expired")
		}
		hash, challenge := sha256.Sum256([]byte(in.code.Value())), sha256.Sum256([]byte(in.verifier.Value()))
		code, err := s.applications.ConsumeAuthorizationCodeTx(ctx, q, hash[:], client.ID, in.redirectURI)
		if err != nil {
			return err
		}
		if code.MemberID == "" || !code.ExpiresAt.After(time.Now().UTC()) || code.CodeChallengeMethod != "S256" ||
			subtle.ConstantTimeCompare([]byte(code.CodeChallenge), []byte(base64.RawURLEncoding.EncodeToString(challenge[:]))) != 1 {
			return apierr.New("invalid_grant", "authorization code is invalid or expired")
		}
		if in.resource != "" && in.resource != code.Resource {
			return apierr.New("invalid_target", "resource does not match the authorization request")
		}
		if code.Resource != client.ClientID {
			return apierr.New("invalid_target", "resource is not registered for this client")
		}
		if err := member.LockChainsTx(ctx, q, code.MemberID); err != nil {
			return err
		}
		ag, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: code.MemberID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "authorization code is invalid or expired")
		}
		if err != nil {
			return err
		}
		if ag.OauthClientID.String != client.ClientID || ag.Source.String != "oauth" ||
			code.MemberTokenEpoch <= 0 || code.MemberTokenEpoch != ag.TokenEpoch || !code.ExpiresAt.After(time.Now().UTC()) {
			return apierr.New("invalid_grant", "authorization code is invalid or expired")
		}
		installed, err := s.applications.OAuthClientInstalledTx(ctx, q, client.ID, ag.SpaceID)
		if err != nil {
			return err
		}
		if !installed {
			return apierr.New("invalid_grant", "application is not installed")
		}
		ctx = audit.WithCaller(ctx, audit.Caller{UserID: code.UserID, ApplicationID: client.ID, CredentialType: "oauth_authorization_code"})
		tokens, err = s.sessions.CreateAgentAccessTx(ctx, q, ag.ID, ag.SpaceID, code.Resource)
		if err != nil {
			return err
		}
		tokens.RefreshToken, err = s.agents.CreateOAuthRefreshCredentialTx(ctx, q, ag.ID, time.Time{})
		scope = code.Scope
		return err
	})
	if err != nil {
		return session.Tokens{}, "", err
	}
	return tokens, scope, nil
}

func (s tokenService) refresh(ctx context.Context, credentials clientCredentials, raw secret.String, resource, scope string) (session.Tokens, string, error) {
	var tokens session.Tokens
	var issuedScope string
	var replayed bool
	err := s.applications.Store.InTx(ctx, func(q *db.Queries) error {
		client, err := s.applications.AuthenticateOAuthClientMethodTx(ctx, q, credentials.id, credentials.secret.Value(), credentials.method)
		if err != nil {
			return err
		}
		resource = strings.TrimSpace(resource)
		if resource == "" {
			resource = client.ClientID
		}
		if resource != client.ClientID && resource != security.DefaultApplicationAudience {
			return apierr.New("invalid_target", "resource is not registered for this client")
		}
		requested := uniqueScopes(strings.Fields(scope))
		if len(requested) > 256 || (resource == security.DefaultApplicationAudience && len(requested) == 0) {
			return apierr.New("invalid_scope", "an explicit scope of at most 256 permissions is required")
		}
		ctx = audit.WithCaller(ctx, audit.Caller{ApplicationID: client.ID, CredentialType: "oauth_refresh_token"})
		credential, next, replay, err := s.agents.RotateOAuthRefreshForClientTx(ctx, q, raw.Value(), client.ClientID)
		if err != nil {
			return err
		}
		if replay {
			// Commit the family revocation without signing or returning a token.
			replayed = true
			return nil
		}
		installed, err := s.applications.OAuthClientInstalledTx(ctx, q, client.ID, credential.SpaceID)
		if err != nil {
			return err
		}
		if !installed {
			return apierr.New("invalid_grant", "application is not installed")
		}
		if len(requested) > 0 {
			if s.authorization == nil {
				return apierr.New("temporarily_unavailable", "scope authorization is unavailable")
			}
			consented, consentErr := q.ListOAuthConsentPermissions(ctx, db.ListOAuthConsentPermissionsParams{MemberID: credential.MemberID})
			if consentErr != nil {
				return consentErr
			}
			for _, permission := range requested {
				if !scopeContains(consented, permission) {
					return apierr.New("invalid_scope", "requested scope is outside user consent")
				}
			}
			if _, err := s.oauthScopesTx(ctx, q, security.Claims{Subject: credential.MemberID}, credential.SpaceID, credential.MemberID, client, requested, true); err != nil {
				return err
			}
			tokens, err = s.sessions.CreateAgentScopedAccessTx(ctx, q, credential.MemberID, credential.SpaceID, resource, requested)
			issuedScope = strings.Join(requested, " ")
		} else {
			tokens, err = s.sessions.CreateAgentAccessTx(ctx, q, credential.MemberID, credential.SpaceID, resource)
		}
		tokens.RefreshToken = next
		return err
	})
	if err != nil {
		return session.Tokens{}, "", err
	}
	if replayed {
		return session.Tokens{}, "", apierr.New("invalid_grant", "OAuth refresh token replayed")
	}
	return tokens, issuedScope, nil
}
