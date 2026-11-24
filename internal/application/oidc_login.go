package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
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
	"github.com/plystra/auth/internal/session"
)

const OIDCLoginRequestPrefix = "olr_"

type OIDCLoginRequestInput struct {
	ApplicationID string
	ClientID      string
	RedirectURI   string
	Scope         []string
	State         string
	Nonce         string
	CodeChallenge string
	MaxAge        *int32
}

type OIDCLoginRequest struct {
	ID          string        `json:"-"`
	RequestID   secret.String `json:"request_id"`
	ExpiresAt   time.Time     `json:"expires_at"`
	ClientID    string        `json:"client_id"`
	ClientName  string        `json:"client_name"`
	Scopes      []string      `json:"scopes"`
	RedirectURI string        `json:"redirect_uri"`
}

func (s *Service) StartOIDCLogin(ctx context.Context, in OIDCLoginRequestInput) (OIDCLoginRequest, error) {
	return s.startOIDCLogin(ctx, in, false)
}

func (s *Service) StartOIDCBrowserLogin(ctx context.Context, in OIDCLoginRequestInput) (OIDCLoginRequest, error) {
	return s.startOIDCLogin(ctx, in, true)
}

func (s *Service) startOIDCLogin(ctx context.Context, in OIDCLoginRequestInput, browserBound bool) (OIDCLoginRequest, error) {
	if !slices.Contains(in.Scope, "openid") {
		return OIDCLoginRequest{}, apierr.New("invalid_scope", "openid is required for user sign-in")
	}
	scopes := make([]string, 0, len(in.Scope))
	for _, scope := range in.Scope {
		if scope != "openid" && scope != "email" && scope != "profile" {
			return OIDCLoginRequest{}, apierr.New("invalid_scope", "scope is not available for user sign-in")
		}
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	challenge, err := base64.RawURLEncoding.Strict().DecodeString(in.CodeChallenge)
	if err != nil || len(challenge) != sha256.Size || len(in.CodeChallenge) != 43 || in.State == "" || in.Nonce == "" {
		return OIDCLoginRequest{}, apierr.New("invalid_request", "state, nonce and PKCE S256 are required for user sign-in")
	}
	var maxAge pgtype.Int4
	if in.MaxAge != nil {
		if *in.MaxAge < 0 {
			return OIDCLoginRequest{}, apierr.New("invalid_request", "max_age must be nonnegative")
		}
		maxAge = pgtype.Int4{Int32: *in.MaxAge, Valid: true}
	}
	handle, digest := newOIDCLoginCredential(OIDCLoginRequestPrefix)
	var request OIDCLoginRequest
	err = s.Store.InTx(ctx, func(q *db.Queries) error {
		client, err := s.OAuthClientByIDTx(ctx, q, in.ApplicationID)
		if err != nil {
			return err
		}
		if !client.HumanOIDCEnabled || client.ClientID != in.ClientID || !slices.Contains(client.RedirectURIs, in.RedirectURI) {
			return apierr.New("invalid_request", "client is not registered for this sign-in request")
		}
		requestID := string(ids.New[ids.ID]("lrq"))
		expires, err := q.CreateOIDCLoginRequest(ctx, db.CreateOIDCLoginRequestParams{
			ID: requestID, RequestHash: digest, ApplicationID: client.ID, BrowserBound: browserBound,
			ApplicationGeneration: client.HumanOIDCGeneration, RedirectUri: in.RedirectURI,
			Scope: strings.Join(scopes, " "), State: in.State, Nonce: in.Nonce, CodeChallenge: in.CodeChallenge,
			MaxAuthenticationAge: maxAge,
		})
		if err != nil {
			return err
		}
		request = OIDCLoginRequest{
			ID: requestID, RequestID: handle, ExpiresAt: expires.Time, ClientID: client.ClientID,
			ClientName: client.Name, Scopes: scopes, RedirectURI: in.RedirectURI,
		}
		return nil
	})
	if err != nil {
		return OIDCLoginRequest{}, err
	}
	return request, nil
}

func newOIDCLoginCredential(prefix string) (secret.String, []byte) {
	var entropy [32]byte
	_, _ = rand.Read(entropy[:])
	raw := secret.New(prefix + base64.RawURLEncoding.EncodeToString(entropy[:]))
	digest := sha256.Sum256([]byte(raw.Value()))
	return raw, digest[:]
}

// BindOIDCAuthorizationToBrowser exchanges the unbound handle for a browser
// credential without recreating the authorization or extending its deadline.
func (s *Service) BindOIDCAuthorizationToBrowser(ctx context.Context, handle secret.String) (OIDCLoginRequest, error) {
	invalid := apierr.New("invalid_request", "sign-in request is invalid or expired")
	if !strings.HasPrefix(handle.Value(), OIDCLoginRequestPrefix) || len(handle.Value()) != len(OIDCLoginRequestPrefix)+43 {
		return OIDCLoginRequest{}, invalid
	}
	authorizationHash := sha256.Sum256([]byte(handle.Value()))
	cookie, cookieHash := newOIDCLoginCredential(OIDCLoginRequestPrefix)
	var result OIDCLoginRequest
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		appID, err := q.FindOIDCLoginRequestClient(ctx, db.FindOIDCLoginRequestClientParams{RequestHash: authorizationHash[:]})
		if errors.Is(err, pgx.ErrNoRows) {
			return invalid
		}
		if err != nil {
			return err
		}
		client, err := s.OAuthClientByIDTx(ctx, q, appID)
		if err != nil {
			return err
		}
		if !client.HumanOIDCEnabled {
			return invalid
		}
		request, err := q.BindOIDCAuthorizationToBrowser(ctx, db.BindOIDCAuthorizationToBrowserParams{
			AuthorizationHash: authorizationHash[:], CookieHash: cookieHash,
			ApplicationID: client.ID, ApplicationGeneration: client.HumanOIDCGeneration,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return invalid
		}
		if err != nil {
			return err
		}
		if !slices.Contains(client.RedirectURIs, request.RedirectUri) {
			return invalid
		}
		result = OIDCLoginRequest{
			ID: request.ID, RequestID: cookie, ExpiresAt: request.ExpiresAt.Time, ClientID: client.ClientID,
			ClientName: client.Name, Scopes: strings.Split(request.Scope, " "), RedirectURI: request.RedirectUri,
		}
		return nil
	})
	if err != nil {
		return OIDCLoginRequest{}, err
	}
	return result, nil
}

func (s *Service) DecideOIDCLogin(ctx context.Context, sessions *session.Service, handle, bearer secret.String, decision string) (string, error) {
	return s.decideOIDCLogin(ctx, sessions, handle, bearer, "", decision)
}

func (s *Service) DecideOIDCBrowserLogin(ctx context.Context, sessions *session.Service, id string, handle secret.String, decision string) (string, error) {
	return s.decideOIDCLogin(ctx, sessions, handle, secret.New(""), id, decision)
}

func (s *Service) decideOIDCLogin(ctx context.Context, sessions *session.Service, handle, bearer secret.String, browserID, decision string) (string, error) {
	if s == nil || s.Store == nil || sessions == nil {
		return "", apierr.New("temporarily_unavailable", "user sign-in is unavailable")
	}
	if !strings.HasPrefix(handle.Value(), OIDCLoginRequestPrefix) || len(handle.Value()) != len(OIDCLoginRequestPrefix)+43 ||
		(decision != "approve" && decision != "deny") {
		return "", apierr.New("invalid_request", "sign-in decision is invalid")
	}
	invalidRequest := apierr.New("invalid_request", "sign-in request is invalid or expired")
	invalidToken := apierr.New("invalid_token", "an active user session is required")
	hash := sha256.Sum256([]byte(handle.Value()))
	var redirectTo string
	isBrowser := browserID != ""
	err := s.Store.InTx(ctx, func(q *db.Queries) error {
		var claims security.Claims
		if !isBrowser {
			signer, err := sessions.CurrentSigner(ctx, q)
			if err != nil {
				return err
			}
			claims, err = signer.Verify(bearer.Value(), time.Now().UTC(), security.DefaultApplicationAudience)
			if err != nil || claims.Type != "user" || claims.SessionID == "" {
				return invalidToken
			}
		}
		appID, err := q.FindOIDCLoginRequestClient(ctx, db.FindOIDCLoginRequestClientParams{RequestHash: hash[:], BrowserBound: isBrowser})
		if errors.Is(err, pgx.ErrNoRows) {
			return invalidRequest
		}
		if err != nil {
			return err
		}
		client, err := s.OAuthClientByIDTx(ctx, q, appID)
		if err != nil {
			return err
		}
		if !client.HumanOIDCEnabled {
			return invalidRequest
		}
		if isBrowser {
			browser, err := q.GetPendingOIDCBrowserInteraction(ctx, db.GetPendingOIDCBrowserInteractionParams{ID: browserID, RequestHash: hash[:]})
			if errors.Is(err, pgx.ErrNoRows) {
				return invalidRequest
			}
			if err != nil {
				return err
			}
			var active bool
			claims, active, err = sessions.CheckOIDCBrowserSessionTx(ctx, q, browser.BrowserSessionID.String)
			if err != nil {
				return err
			}
			if !active {
				return invalidToken
			}
		}
		user, err := q.LockUserForAuthorization(ctx, db.LockUserForAuthorizationParams{ID: claims.Subject})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && user.Status != "active" {
			return invalidToken
		}
		if err != nil {
			return err
		}
		if err := member.LockChainsTx(ctx, q, claims.MemberID); err != nil {
			return err
		}
		if _, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: claims.SessionID}); errors.Is(err, pgx.ErrNoRows) {
			return invalidToken
		} else if err != nil {
			return err
		}
		status := "denied"
		if decision == "approve" {
			status = "approved"
		}
		request, err := q.FinishOIDCLoginRequest(ctx, db.FinishOIDCLoginRequestParams{
			Status: status, RequestHash: hash[:], ApplicationID: client.ID, ApplicationGeneration: client.HumanOIDCGeneration,
			BrowserBound: isBrowser,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return invalidRequest
		}
		if err != nil {
			return err
		}
		if !slices.Contains(client.RedirectURIs, request.RedirectUri) {
			return invalidRequest
		}
		redirect, err := url.Parse(request.RedirectUri)
		if err != nil {
			return invalidRequest
		}
		params := url.Values{"state": {request.State}}
		if decision == "approve" {
			if age := request.MaxAuthenticationAge; age.Valid {
				evidence, err := q.GetOIDCSessionAuthenticationEvidence(ctx, db.GetOIDCSessionAuthenticationEvidenceParams{SessionID: claims.SessionID})
				if err != nil {
					return err
				}
				if !evidence.AuthenticationTime.Valid ||
					(age.Int32 == 0 && evidence.SessionAuthenticationTime.Time.Before(request.CreatedAt.Time)) ||
					!security.OIDCAuthenticationFreshEnough(evidence.AuthenticationTime.Time, request.CreatedAt.Time, age.Int32, evidence.Upstream, time.Now().UTC()) {
					return apierr.New("login_required", "authenticate again to approve this sign-in")
				}
			}
			code, digest := newOIDCLoginCredential("olc_")
			inserted, err := q.IssueOIDCLoginCode(ctx, db.IssueOIDCLoginCodeParams{
				ID: string(ids.New[ids.ID]("lcd")), CodeHash: digest, UserID: claims.Subject,
				SessionID: claims.SessionID, RequestID: request.ID,
			})
			if err != nil {
				return err
			}
			if inserted != 1 {
				return invalidRequest
			}
			params.Set("code", code.Value())
		} else {
			params.Set("error", "access_denied")
		}
		publisher, err := q.GetSpace(ctx, db.GetSpaceParams{ID: client.SpaceID})
		if err != nil {
			return err
		}
		credential := "user_access_token"
		if isBrowser {
			credential = "oidc_browser_interaction"
		}
		if err := audit.WriteAccountEvent(ctx, q, audit.SecurityEvent{
			ActorType: "user", ActorID: claims.Subject, UserID: claims.Subject, ApplicationID: client.ID,
			Action: "oidc.consent." + decision, Outcome: "success", CredentialType: credential, PolicyVersion: publisher.PolicyVersion,
			Resource: audit.Resource{Type: "application", ID: client.ID, SpaceID: client.SpaceID},
			Metadata: map[string]string{"authorization_request_id": request.ID, "scope": request.Scope},
		}); err != nil {
			return err
		}
		// Expiry can advance while waiting for any of the locks or the audit insert.
		var current security.Claims
		var active bool
		if isBrowser {
			current, active, err = sessions.CheckOIDCBrowserSessionTx(ctx, q, claims.SessionID)
		} else {
			current, active, err = sessions.IntrospectTx(ctx, q, bearer.Value(), security.DefaultApplicationAudience)
		}
		if err != nil {
			return err
		}
		if !active || current.Type != "user" || current.Subject != claims.Subject || current.SessionID != claims.SessionID || current.MemberID != claims.MemberID {
			return invalidToken
		}
		if !request.ExpiresAt.Time.After(time.Now().UTC()) {
			return invalidRequest
		}
		redirect.RawQuery = oidcLoginResponseQuery(redirect.RawQuery, params)
		redirectTo = redirect.String()
		return nil
	})
	if err != nil {
		return "", err
	}
	return redirectTo, nil
}

func oidcLoginResponseQuery(registered string, response url.Values) string {
	// Retain the registered query's original encoding and field order. Only the
	// issuer supplies code, error and state in the authorization response.
	var fields []string
	for field := range strings.SplitSeq(registered, "&") {
		params, err := url.ParseQuery(field)
		if err != nil || len(params) == 0 || params.Has("code") || params.Has("error") || params.Has("state") {
			continue
		}
		fields = append(fields, field)
	}
	return strings.Join(append(fields, response.Encode()), "&")
}
