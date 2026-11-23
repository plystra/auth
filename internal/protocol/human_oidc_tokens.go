package protocol

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
)

const userInfoPrefix = "oui_"

type humanLoginTokens struct {
	AccessToken secret.String `json:"access_token"`
	IDToken     secret.String `json:"id_token"`
	TokenType   string        `json:"token_type"`
	ExpiresIn   int64         `json:"expires_in"`
	Scope       string        `json:"scope"`
}

func (h HTTP) exchangeHumanLogin(w http.ResponseWriter, r *http.Request) {
	if h.Applications == nil || h.Sessions == nil {
		writeStandardOAuthError(w, apierr.New("temporarily_unavailable", "human login exchange is unavailable"))
		return
	}
	if r.PostForm.Has("scope") || r.PostForm.Has("resource") {
		writeStandardOAuthError(w, apierr.New("invalid_request", "supply the original authorization code in the form body"))
		return
	}
	client, err := oauthClientCredentials(r, true)
	if err != nil {
		writeStandardOAuthError(w, err)
		return
	}
	tokens, err := (tokenService{applications: h.Applications, sessions: h.Sessions}).humanLoginCode(r.Context(), codeExchangeInput{
		client: client, code: secret.New(r.PostForm.Get("code")),
		redirectURI: r.PostForm.Get("redirect_uri"), verifier: secret.New(r.PostForm.Get("code_verifier")),
	})
	if err != nil {
		writeStandardOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func invalidLoginCode() error {
	return apierr.New("invalid_grant", "authorization code is invalid or expired")
}

func loginStateError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return invalidLoginCode()
	}
	return err
}

var pkceVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

func (s tokenService) humanLoginCode(ctx context.Context, in codeExchangeInput) (humanLoginTokens, error) {
	hash := sha256.Sum256([]byte(in.code.Value()))
	challenge := sha256.Sum256([]byte(in.verifier.Value()))
	var tokens humanLoginTokens
	err := s.applications.Store.InTx(ctx, func(q *db.Queries) error {
		client, err := s.applications.AuthenticateOAuthClientMethodTx(ctx, q, in.client.id, in.client.secret.Value(), in.client.method)
		if err != nil {
			return err
		}
		if !pkceVerifier.MatchString(in.verifier.Value()) || !client.HumanOIDCEnabled || !slices.Contains(client.RedirectURIs, in.redirectURI) {
			return invalidLoginCode()
		}
		ref, err := q.GetOIDCCodeSession(ctx, db.GetOIDCCodeSessionParams{ApplicationID: client.ID, CodeHash: hash[:], RedirectUri: in.redirectURI})
		if err != nil {
			return loginStateError(err)
		}
		// Account and binding revocation take the user and member before the session.
		// After acquiring the same locks, consume against the complete live session.
		if _, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: ref.UserID}); err != nil {
			return loginStateError(err)
		}
		if err := member.LockChainsTx(ctx, q, ref.MemberID.String); err != nil {
			return err
		}
		if _, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: ref.SessionID}); err != nil {
			return loginStateError(err)
		}
		code, err := q.ConsumeOIDCLoginCode(ctx, db.ConsumeOIDCLoginCodeParams{CodeID: ref.ID, CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:])})
		if err != nil {
			return loginStateError(err)
		}
		settings, err := q.GetInstanceSettings(ctx)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Second)
		expiry := now.Add(time.Duration(settings.AccessTokenTtlSeconds) * time.Second)
		if code.SessionExpiresAt.Time.Before(expiry) {
			expiry = code.SessionExpiresAt.Time.Truncate(time.Second)
		}
		if !expiry.After(now) {
			return invalidLoginCode()
		}
		signer, err := s.sessions.CurrentSigner(ctx, q)
		if err != nil {
			return err
		}
		idToken, err := signer.SignHumanIDToken(security.HumanIDToken{
			UserID: ids.UserID(code.UserID), ClientID: client.ClientID, Nonce: secret.New(code.Nonce), IssuedAt: now, ExpiresAt: expiry,
		})
		if err != nil {
			return err
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return err
		}
		access := secret.New(userInfoPrefix + base64.RawURLEncoding.EncodeToString(entropy[:]))
		digest := sha256.Sum256([]byte(access.Value()))
		if err := q.CreateOIDCUserInfoToken(ctx, db.CreateOIDCUserInfoTokenParams{
			CodeID: code.ID, TokenHash: digest[:], ExpiresAt: pgtype.Timestamptz{Time: expiry, Valid: true},
		}); err != nil {
			return err
		}
		if err := audit.WriteAccountEvent(ctx, q, audit.SecurityEvent{
			ActorType: "user", ActorID: code.UserID, UserID: code.UserID, ApplicationID: client.ID,
			Action: "oidc.login.exchange", Outcome: "success", CredentialType: "oidc_authorization_code",
			Resource: audit.Resource{Type: "application", ID: client.ID, SpaceID: client.SpaceID},
		}); err != nil {
			return err
		}
		completed := time.Now().UTC()
		if !expiry.After(completed) || !code.ExpiresAt.Time.After(completed) {
			return invalidLoginCode()
		}
		tokens = humanLoginTokens{AccessToken: access, IDToken: idToken, TokenType: "Bearer", ExpiresIn: expiry.Unix() - completed.Unix(), Scope: code.Scope}
		return nil
	})
	if err != nil {
		return humanLoginTokens{}, err
	}
	return tokens, nil
}

func (h HTTP) humanUserInfo(w http.ResponseWriter, r *http.Request, access string) {
	if h.Applications == nil {
		writeStandardOAuthError(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
		return
	}
	hash := sha256.Sum256([]byte(access))
	row, err := h.Applications.Store.Queries().GetOIDCUserInfo(r.Context(), db.GetOIDCUserInfoParams{TokenHash: hash[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeStandardOAuthError(w, apierr.New("invalid_token", "the access token is invalid"))
		return
	}
	if err != nil {
		writeStandardOAuthError(w, apierr.New("temporarily_unavailable", "userinfo is unavailable"))
		return
	}
	scopes := strings.Fields(row.Scope)
	body := map[string]any{"sub": row.UserID}
	if slices.Contains(scopes, "email") {
		body["email"], body["email_verified"] = row.Email, row.EmailVerifiedAt.Valid
	}
	if slices.Contains(scopes, "profile") {
		if row.DisplayName != "" {
			body["name"] = row.DisplayName
		}
		if row.AvatarUrl != "" {
			body["picture"] = row.AvatarUrl
		}
	}
	writeJSON(w, http.StatusOK, body)
}
