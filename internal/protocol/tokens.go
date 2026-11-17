package protocol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

func (s tokenService) delegated(ctx context.Context, subject, actor secret.String, requested []string, resource string) (session.Tokens, error) {
	var tokens session.Tokens
	err := s.agents.Store.InTx(ctx, func(q *db.Queries) error {
		credential, err := s.agents.AuthenticateKeyTx(ctx, q, actor.Value())
		if err != nil {
			return exchangeCredentialError(err)
		}
		if err := s.agents.ValidateActiveTx(ctx, q, credential.MemberID); err != nil {
			return exchangeCredentialError(err)
		}
		// The authenticated child's persisted owner chain is locked before
		// reading the parent JWT's current revocation epoch and authority.
		parent, active, err := s.sessions.IntrospectTx(ctx, q, subject.Value(), security.DefaultApplicationAudience)
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
		ctx = audit.WithCaller(ctx, audit.Caller{CredentialType: "agent_token_exchange"})
		tokens, err = s.sessions.CreateAgentDelegatedAccessTx(ctx, q, credential.MemberID, credential.SpaceID, resource, parent.Subject, requested, parent.ExpiresAt)
		return err
	})
	if err != nil {
		return session.Tokens{}, err
	}
	return tokens, nil
}

func exchangeCredentialError(err error) error {
	var public *apierr.Error
	if errors.As(err, &public) && public.Code == "UNAUTHENTICATED" {
		return apierr.New("invalid_grant", "agent credential is invalid")
	}
	return err
}

type codeExchangeInput struct {
	clientID, redirectURI, resource string
	clientSecret, code, verifier    secret.String
}

func (s tokenService) authorizationCode(ctx context.Context, in codeExchangeInput) (session.Tokens, string, error) {
	var tokens session.Tokens
	var scope string
	err := s.applications.Store.InTx(ctx, func(q *db.Queries) error {
		client, err := s.applications.AuthenticateOAuthClientTx(ctx, q, in.clientID, in.clientSecret.Value())
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
		ag, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: code.MemberID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.New("invalid_grant", "authorization code is invalid or expired")
		}
		if err != nil {
			return err
		}
		if ag.OauthClientID.String != client.ClientID || ag.Source.String != "oauth" {
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

func (s tokenService) refresh(ctx context.Context, clientID string, clientSecret, raw secret.String, resource string) (session.Tokens, error) {
	var tokens session.Tokens
	var replayed bool
	err := s.applications.Store.InTx(ctx, func(q *db.Queries) error {
		client, err := s.applications.AuthenticateOAuthClientTx(ctx, q, clientID, clientSecret.Value())
		if err != nil {
			return err
		}
		resource = strings.TrimSpace(resource)
		if resource == "" {
			resource = client.ClientID
		}
		if resource != client.ClientID {
			return apierr.New("invalid_target", "resource is not registered for this client")
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
		tokens, err = s.sessions.CreateAgentAccessTx(ctx, q, credential.MemberID, credential.SpaceID, resource)
		tokens.RefreshToken = next
		return err
	})
	if err != nil {
		return session.Tokens{}, err
	}
	if replayed {
		return session.Tokens{}, apierr.New("invalid_grant", "OAuth refresh token replayed")
	}
	return tokens, nil
}
