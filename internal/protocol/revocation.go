package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
)

func (h HTTP) revoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := parseOAuthForm(r); err != nil {
		writeOAuthEndpointError(w, err, "oauth/revoke")
		return
	}
	client, err := oauthClientCredentials(r, false)
	if err != nil {
		writeOAuthEndpointError(w, err, "oauth/revoke")
		return
	}
	raw := secret.New(strings.TrimSpace(r.PostForm.Get("token")))
	if raw.Value() == "" {
		writeOAuthEndpointError(w, apierr.New("invalid_request", "token is required"), "oauth/revoke")
		return
	}
	if h.Applications == nil {
		writeOAuthEndpointError(w, apierr.New("temporarily_unavailable", "token revocation is unavailable"), "oauth/revoke")
		return
	}
	service := tokenService{applications: h.Applications, agents: h.Agents, sessions: h.Sessions}
	if err := service.revoke(r.Context(), client, raw); err != nil {
		writeOAuthEndpointError(w, err, "oauth/revoke")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s tokenService) revoke(ctx context.Context, credentials clientCredentials, raw secret.String) error {
	return s.applications.Store.InTx(ctx, func(q *db.Queries) error {
		authenticatedApp := ""
		if credentials.id != "" {
			client, err := s.applications.AuthenticateOAuthClientMethodTx(ctx, q, credentials.id, credentials.secret.Value(), credentials.method)
			if err != nil {
				return err
			}
			authenticatedApp = client.ID
		}
		if strings.HasPrefix(raw.Value(), userInfoPrefix) {
			hash := sha256.Sum256([]byte(raw.Value()))
			owner, err := q.GetOIDCUserInfoApplication(ctx, db.GetOIDCUserInfoApplicationParams{TokenHash: hash[:]})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			allowed, err := revocationAllowed(ctx, q, authenticatedApp, owner)
			if err != nil || !allowed {
				return err
			}
			return q.RevokeOIDCUserInfoForApplication(ctx, db.RevokeOIDCUserInfoForApplicationParams{TokenHash: hash[:], ApplicationID: owner})
		}
		return s.revokeAgentTokenTx(ctx, q, authenticatedApp, raw)
	})
}

// An explicitly authenticated client can only revoke its own token. Possession-only
// revocation remains available to existing clients; the registered method is read
// under the application lock before locking any Agent member or refresh credential.
func revocationAllowed(ctx context.Context, q *db.Queries, authenticatedApp, ownerApp string) (bool, error) {
	if authenticatedApp != "" {
		return authenticatedApp == ownerApp, nil
	}
	if ownerApp == "" {
		return true, nil
	}
	owner, err := q.GetOAuthClientByID(ctx, db.GetOAuthClientByIDParams{ID: ownerApp})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if owner.TokenEndpointAuthMethod == "client_secret_basic" {
		return false, apierr.New("invalid_client", "OAuth client authentication failed")
	}
	return true, nil
}

func (s tokenService) revokeAgentTokenTx(ctx context.Context, q *db.Queries, authenticatedApp string, raw secret.String) error {
	refresh := strings.HasPrefix(raw.Value(), "ply_rt_")
	var subject string
	if refresh {
		if s.agents == nil {
			return apierr.New("temporarily_unavailable", "agent revocation is unavailable")
		}
		id, err := s.agents.OAuthRefreshMemberTx(ctx, q, raw.Value())
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		subject = id
	} else {
		subject = jwtSubjectHint(raw)
		if subject == "" {
			return nil
		}
		if s.agents == nil || s.sessions == nil {
			return apierr.New("temporarily_unavailable", "agent revocation is unavailable")
		}
	}
	hint, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if hint.Source.String != "oauth" {
		return nil
	}
	clientID, appID := hint.OauthClientID.String, ""
	if clientID != "" {
		ref, err := q.GetApplicationByClientID(ctx, db.GetApplicationByClientIDParams{ClientID: clientID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		appID = ref.ID
	}
	allowed, authErr := revocationAllowed(ctx, q, authenticatedApp, appID)
	if refresh {
		if authErr != nil || !allowed {
			return authErr
		}
		caller := audit.Caller{CredentialType: "oauth_refresh_token", ApplicationID: appID}
		_, err := s.agents.RevokeOAuthRefreshTokenTx(audit.WithCaller(ctx, caller), q, raw.Value(), &clientID)
		return err
	}

	// A JWT subject only selects locks. Check signature and live state before
	// exposing any missing-client error for a token supplied without credentials.
	if err := member.LockChainsTx(ctx, q, subject); err != nil {
		return err
	}
	root, err := q.GetAgentMember(ctx, db.GetAgentMemberParams{MemberID: subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if root.Source.String != "oauth" || root.OauthClientID.String != clientID {
		return nil
	}
	audience := clientID
	if audience == "" {
		audience = security.DefaultApplicationAudience
	}
	claims, active, err := s.sessions.IntrospectTx(ctx, q, raw.Value(), audience)
	if err != nil {
		return err
	}
	if !active && audience != security.DefaultApplicationAudience {
		claims, active, err = s.sessions.IntrospectTx(ctx, q, raw.Value(), security.DefaultApplicationAudience)
		if err != nil {
			return err
		}
	}
	if !active || claims.Type != "agent" || claims.Subject != subject {
		return nil
	}
	if authErr != nil || !allowed {
		return authErr
	}
	caller := audit.Caller{CredentialType: "agent_access_token", ApplicationID: appID}
	return s.agents.RevokeOAuthTx(audit.WithCaller(ctx, caller), q, subject)
}

func jwtSubjectHint(raw secret.String) string {
	parts := strings.Split(raw.Value(), ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var hint struct {
		Subject string `json:"sub"`
	}
	if json.Unmarshal(payload, &hint) != nil {
		return ""
	}
	return hint.Subject
}
