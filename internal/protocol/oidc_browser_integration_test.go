package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

const browserFixturePassword = "synthetic-browser-sign-in-password"

type interactionResponse struct {
	ID               string `json:"id"`
	NextStep         string `json:"next_step"`
	Email            string `json:"signed_in_email"`
	RedirectTo       string `json:"redirect_to"`
	SSOConnectionID  string `json:"sso_connection_id"`
	AuthorizationURL string `json:"authorization_url"`
}

type oidcBrowser struct {
	rp     *humanRP
	client *http.Client
}

func newOIDCBrowser(t *testing.T, rp *humanRP) oidcBrowser {
	t.Helper()
	hash, err := security.DefaultPasswordHasher().Hash(browserFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(t.Context(), "UPDATE users SET password_hash=$1 WHERE id='usr_human_rp'", hash); err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return oidcBrowser{rp: rp, client: &http.Client{Transport: rp.host.Client().Transport, Jar: jar, Timeout: 10 * time.Second}}
}

func (b oidcBrowser) request(t *testing.T, method, path string, payload map[string]string, origin, key string, status int) (interactionResponse, []*http.Cookie) {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), method, b.rp.host.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		var failure struct {
			Error struct{ Code string }
		}
		_ = json.Unmarshal(data, &failure)
		t.Fatalf("%s %s returned HTTP %d (%s), want %d", method, path, res.StatusCode, failure.Error.Code, status)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("interaction response can be cached")
	}
	if bytes.Contains(data, []byte(`"access_token"`)) || bytes.Contains(data, []byte(`"refresh_token"`)) || bytes.Contains(data, []byte(`"olr_`)) {
		t.Fatal("interaction exposed a session credential or opaque handle to page code")
	}
	var envelope struct {
		Data interactionResponse `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal("invalid interaction response")
	}
	return envelope.Data, res.Cookies()
}

func (b oidcBrowser) requestParameters(t *testing.T, verifier, state, nonce string) map[string]string {
	t.Helper()
	cfg := b.rp.config
	cfg.Scopes = []string{"openid", "email"}
	next, err := url.Parse(cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
	if err != nil {
		t.Fatal(err)
	}
	params := make(map[string]string)
	for name, values := range next.Query() {
		params[name] = values[0]
	}
	return params
}

func (b oidcBrowser) begin(t *testing.T, verifier, state, nonce string) (string, *http.Cookie) {
	t.Helper()
	value, cookies := b.request(t, http.MethodPost, route.OIDCInteractionsPath, b.requestParameters(t, verifier, state, nonce), b.rp.host.URL, "", http.StatusCreated)
	if !strings.HasPrefix(value.ID, "lrq_") || value.NextStep != "identify" || len(cookies) != 1 {
		t.Fatal("hosted sign-in did not create a browser interaction")
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-plystra-oidc" || cookie.Value == "" || !cookie.HttpOnly ||
		!cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" || cookie.Path != "/" ||
		!cookie.Expires.After(time.Now()) {
		t.Fatal("browser interaction cookie is not private, host-bound and short-lived")
	}
	return route.OIDCInteractionsPath + "/" + value.ID, cookie
}

func (b oidcBrowser) signIn(t *testing.T, path string, secondFactor bool) {
	t.Helper()
	identified, _ := b.request(t, http.MethodPost, path+"/identify", map[string]string{"email": "rp@example.test", "method": "password"}, b.rp.host.URL, "", http.StatusOK)
	if identified.NextStep != "password" {
		t.Fatal("password authentication was not offered")
	}
	result, _ := b.request(t, http.MethodPost, path+"/authenticate", map[string]string{"password": browserFixturePassword}, b.rp.host.URL, "", http.StatusOK)
	if secondFactor {
		if result.NextStep != "totp" {
			t.Fatal("password authentication bypassed the registered second factor")
		}
		code, err := totp.GenerateCode(b.rp.factorSecret.Value(), time.Now().UTC().Add(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		result, _ = b.request(t, http.MethodPost, path+"/authenticate", map[string]string{"mfa_code": code}, b.rp.host.URL, "", http.StatusOK)
	}
	if result.NextStep != "consent" {
		t.Fatal("successful sign-in did not make consent available")
	}
}

func TestOIDCBrowserInteractionCompletesAtIndependentHTTPSCallback(t *testing.T) {
	rp := humanRPWithAuthMethod(t, true)
	browser := newOIDCBrowser(t, rp)
	received := make(chan url.Values, 1)
	callback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.Query()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(callback.Close)
	rp.config.RedirectURL = callback.URL + "/callback"
	if _, err := rp.st.Pool.Exec(t.Context(), "UPDATE applications SET redirect_uris=jsonb_build_array($1::text) WHERE client_id=$2", rp.config.RedirectURL, rp.config.ClientID); err != nil {
		t.Fatal(err)
	}
	verifier, state, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	path, _ := browser.begin(t, verifier, state, nonce)
	browser.signIn(t, path, true)
	reopened, _ := browser.request(t, http.MethodGet, path, nil, "", "", http.StatusOK)
	if reopened.NextStep != "consent" || reopened.Email != "rp@example.test" {
		t.Fatal("browser could not reopen its authenticated interaction")
	}
	browser.request(t, http.MethodGet, "/v1/me", nil, "", "", http.StatusUnauthorized)
	consent, cookies := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
	if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatal("successful consent did not clear the cookie")
	}
	callbackURL, err := url.Parse(consent.RedirectTo)
	if err != nil || callbackURL.Scheme+"://"+callbackURL.Host+callbackURL.Path != rp.config.RedirectURL {
		t.Fatal("consent selected a different callback")
	}
	res, err := callback.Client().Get(consent.RedirectTo)
	if err != nil {
		t.Fatal("registered HTTPS callback failed")
	}
	_ = res.Body.Close()
	query := <-received
	if res.StatusCode != http.StatusNoContent || query.Get("state") != state || query.Get("code") == "" {
		t.Fatal("the relying party did not receive its bound state and code")
	}
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	token, err := rp.config.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("relying party could not exchange the authorization code")
	}
	raw, _ := token.Extra("id_token").(string)
	idToken, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(ctx, raw)
	if err != nil || idToken.Nonce != nonce || idToken.Subject != "usr_human_rp" || token.RefreshToken != "" {
		t.Fatal("relying party did not receive the expected signed account identity")
	}
	user, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || user.Subject != idToken.Subject || user.Email != "rp@example.test" || !user.EmailVerified {
		t.Fatal("UserInfo did not return the approved identity and email")
	}
}

func TestOIDCBrowserInteractionIsolatedFromBearerAndCrossOriginRequests(t *testing.T) {
	rp := newHumanRP(t)
	browser := newOIDCBrowser(t, rp)
	verifier := oauth2.GenerateVerifier()
	params := browser.requestParameters(t, verifier, "test-state", "test-nonce")
	browser.request(t, http.MethodPost, route.OIDCInteractionsPath, params, "", "", http.StatusForbidden)
	browser.request(t, http.MethodPost, route.OIDCInteractionsPath, params, "https://other.example.test", "", http.StatusForbidden)
	browser.request(t, http.MethodPost, route.OIDCInteractionsPath, params, rp.host.URL, "cache-cookie", http.StatusBadRequest)

	oldPath, _ := browser.begin(t, verifier, "old-state", "old-nonce")
	path, cookie := browser.begin(t, verifier, "test-state", "test-nonce")
	otherBrowser := newOIDCBrowser(t, rp)
	otherBrowser.request(t, http.MethodGet, path, nil, "", "", http.StatusBadRequest)
	browser.request(t, http.MethodGet, oldPath, nil, "", "", http.StatusBadRequest)
	browser.request(t, http.MethodGet, path, nil, "https://other.example.test", "", http.StatusForbidden)
	decision := map[string]string{"decision": "approve"}
	browser.request(t, http.MethodPost, path+"/decision", decision, rp.host.URL, "", http.StatusUnauthorized)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rp.config.Endpoint.AuthURL, strings.NewReader(
		`{"request_id":"`+cookie.Value+`","decision":"approve"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rp.session.AccessToken)
	bearer, err := rp.host.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = bearer.Body.Close()
	if bearer.StatusCode != http.StatusBadRequest {
		t.Fatal("the bearer endpoint accepted a browser interaction")
	}

	browser.signIn(t, path, false)
	browser.request(t, http.MethodPost, path+"/decision", decision, "https://other.example.test", "", http.StatusForbidden)
	browser.request(t, http.MethodPost, path+"/decision", decision, rp.host.URL, "cache-code", http.StatusBadRequest)
	denied, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "deny"}, rp.host.URL, "", http.StatusOK)
	redirect, err := url.Parse(denied.RedirectTo)
	if err != nil || redirect.Query().Get("state") != "test-state" || redirect.Query().Get("error") != "access_denied" || redirect.Query().Has("code") {
		t.Fatal("denial did not preserve state without issuing a code")
	}
	base, err := url.Parse(rp.host.URL)
	if err != nil {
		t.Fatal(err)
	}
	browser.client.Jar.SetCookies(base, []*http.Cookie{cookie})
	browser.request(t, http.MethodPost, path+"/decision", decision, rp.host.URL, "", http.StatusBadRequest)

	revokedPath, _ := browser.begin(t, verifier, "revoked-state", "revoked-nonce")
	browser.signIn(t, revokedPath, false)
	if _, err := rp.st.Pool.Exec(t.Context(), `UPDATE sessions SET revoked_at=now() WHERE id=(
		SELECT browser_session_id FROM oidc_login_requests WHERE id=$1)`, strings.TrimPrefix(revokedPath, route.OIDCInteractionsPath+"/")); err != nil {
		t.Fatal(err)
	}
	browser.request(t, http.MethodPost, revokedPath+"/decision", decision, rp.host.URL, "", http.StatusUnauthorized)
}

func TestOIDCBrowserInteractionRollsBackSessionWhenBindingFails(t *testing.T) {
	rp := newHumanRP(t)
	browser := newOIDCBrowser(t, rp)
	path, _ := browser.begin(t, oauth2.GenerateVerifier(), "binding-state", "binding-nonce")
	browser.request(t, http.MethodPost, path+"/identify", map[string]string{"email": "rp@example.test", "method": "password"}, rp.host.URL, "", http.StatusOK)
	ctx := t.Context()
	if _, err := rp.st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_test_browser_session() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'test interaction binding failure'; END;
		$$;
		CREATE TRIGGER reject_test_browser_session BEFORE UPDATE OF browser_session_id ON oidc_login_requests
		FOR EACH ROW WHEN (NEW.browser_session_id IS NOT NULL) EXECUTE FUNCTION reject_test_browser_session();
	`); err != nil {
		t.Fatal(err)
	}
	password := map[string]string{"password": browserFixturePassword}
	browser.request(t, http.MethodPost, path+"/authenticate", password, rp.host.URL, "", http.StatusServiceUnavailable)
	var sessions, refreshCredentials, activeAttempts int
	if err := rp.st.Pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM sessions WHERE user_id='usr_human_rp'),
		       (SELECT count(*) FROM refresh_tokens),
		       (SELECT count(*) FROM sign_in_attempts WHERE user_id='usr_human_rp' AND consumed_at IS NULL)
	`).Scan(&sessions, &refreshCredentials, &activeAttempts); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || refreshCredentials != 1 || activeAttempts != 1 {
		t.Fatal("failed interaction binding committed credentials or consumed the authentication attempt")
	}
	if _, err := rp.st.Pool.Exec(ctx, "DROP TRIGGER reject_test_browser_session ON oidc_login_requests"); err != nil {
		t.Fatal(err)
	}
	retry, _ := browser.request(t, http.MethodPost, path+"/authenticate", password, rp.host.URL, "", http.StatusOK)
	if retry.NextStep != "consent" {
		t.Fatal("the binding failure left the signed-in browser unable to retry")
	}
}
