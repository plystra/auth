package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/credential"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
	"golang.org/x/oauth2"
)

type humanRP struct {
	st            *store.Store
	host          *httptest.Server
	provider      *oidc.Provider
	config        oauth2.Config
	session       session.Tokens
	signer        *security.Signer
	applicationID string
	factorSecret  secret.String
	workforce     *enterprise.Service
}

func newHumanRP(t *testing.T) *humanRP {
	t.Helper()
	return humanRPWithAuthMethod(t, false)
}

func humanRPWithAuthMethod(t *testing.T, managed bool) *humanRP {
	t.Helper()
	return newConfiguredHumanRP(t, managed, nil)
}

func newConfiguredHumanRP(t *testing.T, managed bool, upstream *oidcTestProvider) *humanRP {
	t.Helper()
	ctx := t.Context()
	database, err := protocolDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users(id,email,email_normalized,password_hash,status,email_verified_at,display_name)
		VALUES ('usr_human_rp','rp@example.test','rp@example.test','unused','active',now(),'RP User')`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, publisher, err := authz.CreateSpace(ctx, "usr_human_rp", "RP Publisher", "rp-publisher")
	if err != nil {
		t.Fatal(err)
	}
	const client = "https://rp.example.test/client"
	const callback = "https://rp.example.test/callback"
	password := "test value:+%"
	key := []byte(strings.Repeat("k", 32))
	if !managed {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO applications(id,space_id,name,client_id,client_secret_hash,redirect_uris,human_oidc_enabled)
			VALUES ('app_human_rp',$1,'Test RP',$2,$3,jsonb_build_array($4::text),true)`, space.ID, client, application.HMACClientSecretHash(key, password), callback); err != nil {
			t.Fatal(err)
		}
	}
	var mux http.ServeMux
	apps := &application.Service{Store: st, HMACKeys: [][]byte{key}}
	sessions := &session.Service{Store: st, HMACKeys: [][]byte{key}, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: 5 * time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: time.Hour}, nil
	}}
	parsers := credential.Validator{Principal: credential.PrincipalParser{Sessions: sessions}}
	var issuer string
	originPolicy := func(_ context.Context, origin string) (bool, error) {
		return origin == issuer || origin == "https://other.example.test", nil
	}
	host := httptest.NewUnstartedServer(route.MiddlewareWithOriginPolicyAndIdempotency(route.Principal, &mux, originPolicy, st, parsers.Validate))
	issuer = "https://" + host.Listener.Addr().String()
	sessions.Signer, err = security.GenerateSigner(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if managed {
		sessions.Factors = &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}
		authz.StepUp, apps.Authorization, apps.StepUp = sessions, authz, sessions
	}
	accounts := &account.Service{Store: st, Sessions: sessions, Passwords: security.DefaultPasswordHasher(), Authorization: authz}
	var workforce *enterprise.Service
	if upstream != nil {
		workforce = &enterprise.Service{Store: st, Authorization: authz, Sessions: sessions, DataKey: secret.New(strings.Repeat("d", 32)), Passwords: accounts.Passwords, HTTPClient: upstream.server.Client(), Issuer: issuer}
		accounts.SignInPolicy, sessions.SpaceSignInPolicy = workforce, workforce
	}
	api := &principal.API{HostedOrigin: issuer, Accounts: accounts, Authorization: authz, Applications: apps, Sessions: sessions, Signer: sessions.Signer, Factors: sessions.Factors, Enterprise: workforce}
	api.Register(humago.New(&mux, route.HumaConfig("RP publisher", "1")))
	(HTTP{Issuer: issuer, HostedOrigin: issuer, Applications: apps, Sessions: sessions, Enterprise: workforce}).Register(&mux)
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		keys, err := sessions.Signer.JWKS()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, keys)
	})
	host.StartTLS()
	t.Cleanup(host.Close)
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, host.Client()), issuer)
	if err != nil {
		t.Fatal("independent relying party could not discover the provider")
	}
	var tokens session.Tokens
	if managed {
		tokens, err = sessions.CreateForMember(ctx, "usr_human_rp", publisher.ID, nil, "publisher", 1)
	} else {
		tokens, err = sessions.Create(ctx, "usr_human_rp", nil, "test-rp-session", 1)
	}
	if err != nil {
		t.Fatal(err)
	}
	config := oauth2.Config{ClientID: client, ClientSecret: password, RedirectURL: callback, Endpoint: provider.Endpoint()}
	config.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	rp := &humanRP{st: st, host: host, provider: provider, config: config, session: tokens, signer: sessions.Signer, workforce: workforce}
	if managed {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
			VALUES ('grt_rp_publisher',$1,'["auth.applications:manage"]',$2,'space',$1,$2)`, space.ID, publisher.ID); err != nil {
			t.Fatal(err)
		}
		enrollment, err := sessions.Factors.BeginTOTP(ctx, "usr_human_rp", "rp@example.test")
		if err != nil {
			t.Fatal(err)
		}
		rp.factorSecret = enrollment.Secret
		rp.registerClient(t, space.ID)
	}
	return rp
}

func (rp *humanRP) authorize(t *testing.T, scopes ...string) (string, string) {
	t.Helper()
	cfg := rp.config
	cfg.Scopes = scopes
	verifier, state, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), "rp-test-nonce"
	resp, err := rp.host.Client().Get(cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
	if err != nil {
		t.Fatal("authorization request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	var request struct {
		ID string `json:"request_id"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&request) != nil || request.ID == "" {
		t.Fatalf("authorization request did not return a handle: %d", resp.StatusCode)
	}
	body, err := json.Marshal(map[string]string{"request_id": request.ID, "decision": "approve"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rp.config.Endpoint.AuthURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+rp.session.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	decision, err := rp.host.Client().Do(req)
	if err != nil {
		t.Fatal("consent request failed")
	}
	defer func() { _ = decision.Body.Close() }()
	var consent struct {
		Redirect string `json:"redirect_to"`
	}
	if decision.StatusCode != http.StatusOK || json.NewDecoder(decision.Body).Decode(&consent) != nil {
		t.Fatalf("consent did not complete: %d", decision.StatusCode)
	}
	u, err := url.Parse(consent.Redirect)
	if err != nil || u.Query().Get("state") != state || !strings.HasPrefix(u.Query().Get("code"), "olc_") {
		t.Fatal("approved request did not bind the callback state and code")
	}
	code := u.Query().Get("code")
	u.RawQuery = ""
	if u.String() != cfg.RedirectURL {
		t.Fatal("unregistered callback")
	}
	return code, verifier
}

func TestHumanOIDCRelyingPartyVerifiesIDTokensDuringSigningKeyOverlap(t *testing.T) {
	rp := newHumanRP(t)
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	config := oidc.Config{ClientID: rp.config.ClientID, SupportedSigningAlgs: []string{oidc.ES256}}
	verifier := rp.provider.Verifier(&config)

	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := rp.provider.Claims(&metadata); err != nil || metadata.JWKSURI != rp.host.URL+"/.well-known/jwks.json" {
		t.Fatal("discovery did not advertise this issuer's JWKS")
	}
	publicKeys := func() map[string]bool {
		t.Helper()
		resp, err := rp.host.Client().Get(metadata.JWKSURI)
		if err != nil {
			t.Fatal("JWKS could not be read")
		}
		defer func() { _ = resp.Body.Close() }()
		var set struct {
			Keys []struct {
				ID string `json:"kid"`
			} `json:"keys"`
		}
		if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&set) != nil {
			t.Fatal("issuer did not publish a readable JWKS")
		}
		keys := make(map[string]bool, len(set.Keys))
		for _, key := range set.Keys {
			if key.ID == "" || keys[key.ID] {
				t.Fatal("issuer published a missing or duplicate key ID")
			}
			keys[key.ID] = true
		}
		return keys
	}
	login := func() string {
		t.Helper()
		code, pkce := rp.authorize(t, "openid")
		tokens, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(pkce))
		if err != nil {
			t.Fatal("authorization code exchange failed")
		}
		raw, ok := tokens.Extra("id_token").(string)
		if !ok || raw == "" {
			t.Fatal("authorization code exchange did not return an ID Token")
		}
		return raw
	}
	old := login()
	if _, err := verifier.Verify(ctx, old); err != nil {
		t.Fatal("relying party rejected the original ID Token")
	}
	next, err := rp.signer.StageNext()
	if err != nil {
		t.Fatal(err)
	}
	if keys := publicKeys(); len(keys) != 1 || keys[next] {
		t.Fatal("the staged key appeared in the active key set")
	}
	if err := rp.signer.PromoteNext(); err != nil {
		t.Fatal(err)
	}
	replacement := login()
	message, err := jws.ParseString(replacement)
	if err != nil || len(message.Signatures()) != 1 {
		t.Fatal("replacement ID Token did not have a single signature")
	}
	if kid, _ := message.Signatures()[0].ProtectedHeaders().KeyID(); kid != next {
		t.Fatal("replacement ID Token was not signed by the promoted key")
	}
	if keys := publicKeys(); len(keys) != 2 || !keys[next] {
		t.Fatal("the promoted and retiring keys were not published together")
	}
	if _, err := verifier.Verify(ctx, replacement); err != nil {
		t.Fatal("an existing relying party did not refresh its keys for the new ID Token")
	}
	fresh, err := oidc.NewProvider(ctx, rp.host.URL)
	if err != nil {
		t.Fatal("a fresh relying party could not discover the issuer")
	}
	for _, raw := range []string{old, replacement} {
		claims, err := fresh.Verifier(&config).Verify(ctx, raw)
		if err != nil || claims.Subject != "usr_human_rp" || claims.Nonce != "rp-test-nonce" {
			t.Fatal("a fresh relying party failed to verify a login during the signing key overlap")
		}
	}
}

func TestHumanOIDCUserInfoAdvertisesBearerChallengeOnUnauthorizedResponses(t *testing.T) {
	rp := newHumanRP(t)
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	var metadata struct {
		UserInfo string `json:"userinfo_endpoint"`
	}
	if err := rp.provider.Claims(&metadata); err != nil || metadata.UserInfo == "" {
		t.Fatal("UserInfo endpoint missing from discovery")
	}
	code, verifier := rp.authorize(t, "openid")
	tokens, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal("code exchange failed")
	}
	idToken, _ := tokens.Extra("id_token").(string)
	if idToken == "" {
		t.Fatal("ID Token missing from code exchange")
	}
	const invalid = `Bearer error="invalid_token"`
	for _, tc := range []struct {
		name, authorization string
		status              int
		challenge           string
	}{
		{"missing credentials", "", http.StatusUnauthorized, "Bearer"},
		{"unsupported scheme", "Basic dGVzdA==", http.StatusUnauthorized, "Bearer"},
		{"ID Token", "Bearer " + idToken, http.StatusUnauthorized, invalid},
		{"unknown UserInfo token", "Bearer oui_unknown", http.StatusUnauthorized, invalid},
		{"unavailable agent credential service", "Bearer ply_ag_fixture", http.StatusServiceUnavailable, ""},
		{"valid UserInfo token", "Bearer " + tokens.AccessToken, http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, metadata.UserInfo, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			res, err := rp.host.Client().Do(req)
			if err != nil {
				t.Fatal("UserInfo request failed")
			}
			defer func() { _ = res.Body.Close() }()
			if res.StatusCode != tc.status || res.Header.Get("WWW-Authenticate") != tc.challenge {
				t.Fatalf("unexpected UserInfo response status=%d or Bearer challenge", res.StatusCode)
			}
		})
	}
}

func TestHumanOIDCInvalidationReachesPendingCodesAndIssuedUserInfo(t *testing.T) {
	for name, change := range map[string]string{
		"disable and reenable login": `UPDATE applications SET human_oidc_enabled=false; UPDATE applications SET human_oidc_enabled=true`,
		"suspend and restore client": `UPDATE applications SET status='suspended'; UPDATE applications SET status='active'`,
		"withdraw public review":     `UPDATE applications SET visibility='public',review_status='pending'`,
		"revoke original session":    `UPDATE sessions SET revoked_at=now()`,
		"expire original session":    `UPDATE sessions SET expires_at=now()`,
		"disable user":               `UPDATE users SET disabled_at=now()`,
	} {
		t.Run(name, func(t *testing.T) {
			rp := newHumanRP(t)
			ctx := oidc.ClientContext(t.Context(), rp.host.Client())
			pending, proof := rp.authorize(t, "openid")
			code, verifier := rp.authorize(t, "openid")
			token, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
			if err != nil {
				t.Fatal("initial code exchange failed")
			}
			if _, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err != nil {
				t.Fatal("initial UserInfo failed")
			}
			if _, err := rp.st.Pool.Exec(ctx, change); err != nil {
				t.Fatal(err)
			}
			if _, err := rp.config.Exchange(ctx, pending, oauth2.VerifierOption(proof)); err == nil {
				t.Fatal("old code survived invalidation")
			}
			if _, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err == nil {
				t.Fatal("old UserInfo access survived invalidation")
			}
		})
	}
}

func TestHumanOIDCAtomicExchangeAndConcurrentRedemption(t *testing.T) {
	rp := newHumanRP(t)
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	code, verifier := rp.authorize(t, "openid")
	if _, err := rp.st.Pool.Exec(ctx, `CREATE FUNCTION reject_exchange() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'oidc.login.exchange' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE CONSTRAINT TRIGGER reject_exchange AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION reject_exchange()`); err != nil {
		t.Fatal(err)
	}
	if token, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier)); err == nil || token != nil {
		t.Fatal("credentials returned after failed commit")
	}
	var credentials, used int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM oidc_userinfo_tokens),
		(SELECT count(*) FROM oidc_login_codes WHERE consumed_at IS NOT NULL)`).Scan(&credentials, &used); err != nil || credentials != 0 || used != 0 {
		t.Fatal("failed commit consumed the code or persisted credentials")
	}
	if _, err := rp.st.Pool.Exec(ctx, "DROP TRIGGER reject_exchange ON audit_logs"); err != nil {
		t.Fatal(err)
	}
	results := make(chan bool, 4)
	for range cap(results) {
		go func() {
			token, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
			results <- err == nil && token.Valid()
		}()
	}
	winners := 0
	for range cap(results) {
		if <-results {
			winners++
		}
	}
	var audit int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM oidc_userinfo_tokens),
		(SELECT count(*) FROM audit_logs WHERE action='oidc.login.exchange' AND user_id='usr_human_rp' AND application_id='app_human_rp')`).
		Scan(&credentials, &audit); err != nil || winners != 1 || credentials != 1 || audit != 1 {
		t.Fatal("expected one committed exchange, token and audit event")
	}
}

func TestHumanOIDCTokenResponsesPreventHTTPStorage(t *testing.T) {
	rp := newHumanRP(t)
	code, verifier := rp.authorize(t, "openid")
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {rp.config.RedirectURL}, "code_verifier": {verifier},
	}
	for _, want := range []int{http.StatusOK, http.StatusBadRequest} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rp.config.Endpoint.TokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(rp.config.ClientID), url.QueryEscape(rp.config.ClientSecret))
		response, err := rp.host.Client().Do(req)
		if err != nil {
			t.Fatal("token request failed")
		}
		_ = response.Body.Close()
		if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" {
			t.Fatalf("token response lacks cache protection or unexpected status: got %d, want %d", response.StatusCode, want)
		}
	}
}

func TestHumanOIDCTokenRejectsAmbiguousFormBeforeExchange(t *testing.T) {
	rp := newHumanRP(t)
	code, verifier := rp.authorize(t, "openid")
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {rp.config.RedirectURL}, "code_verifier": {verifier},
	}
	const formMediaType = "application/x-www-form-urlencoded"
	for _, tc := range []struct{ name, query, contentType, body string }{
		{"grant in URL", "?grant_type=authorization_code", formMediaType, form.Encode()},
		{"empty query", "?", formMediaType, form.Encode()},
		{"repeated grant type", "", formMediaType, "grant_type=unsupported&" + form.Encode()},
		{"repeated code", "", formMediaType, form.Encode() + "&code=duplicate"},
		{"wrong content type", "", "text/plain", form.Encode()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, rp.config.Endpoint.TokenURL+tc.query, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal("could not build token request")
			}
			req.Header.Set("Content-Type", tc.contentType)
			req.SetBasicAuth(url.QueryEscape(rp.config.ClientID), url.QueryEscape(rp.config.ClientSecret))
			response, err := rp.host.Client().Do(req)
			if err != nil {
				t.Fatal("token request failed")
			}
			defer func() { _ = response.Body.Close() }()
			var body struct {
				Error string `json:"error"`
			}
			if response.StatusCode != http.StatusBadRequest || json.NewDecoder(response.Body).Decode(&body) != nil || body.Error != "invalid_request" {
				t.Fatalf("malformed token request was not rejected with invalid_request: HTTP %d", response.StatusCode)
			}
		})
	}
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	tokens, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil || tokens == nil || tokens.AccessToken == "" {
		t.Fatal("valid exchange failed after malformed requests")
	}
}

func TestHumanOIDCExchangeRejectsCodeExpiredWhileWaitingForSession(t *testing.T) {
	rp := newHumanRP(t)
	code, verifier := rp.authorize(t, "openid")
	ctx, cancel := context.WithTimeout(oidc.ClientContext(t.Context(), rp.host.Client()), 15*time.Second)
	defer cancel()
	lockCtx, unlock := context.WithCancel(ctx)
	defer unlock()
	locked, released := make(chan struct{}), make(chan error, 1)
	go func() {
		released <- rp.st.InTx(lockCtx, func(q *db.Queries) error {
			if _, err := q.LockSessionForStepUp(lockCtx, db.LockSessionForStepUpParams{ID: rp.session.SessionID}); err != nil {
				return err
			}
			close(locked)
			<-lockCtx.Done()
			return lockCtx.Err()
		})
	}()
	select {
	case <-locked:
	case err := <-released:
		t.Fatal("could not take the login session lock", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	result := make(chan bool, 1)
	go func() {
		tokens, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		var response *oauth2.RetrieveError
		result <- tokens == nil && errors.As(err, &response) && response.Response.StatusCode == http.StatusBadRequest && response.ErrorCode == "invalid_grant"
	}()
	for {
		var waiting bool
		if err := rp.st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%LockSessionForStepUp%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case <-result:
			t.Fatal("exchange bypassed its original session lock")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	digest := sha256.Sum256([]byte(code))
	if changed, err := rp.st.Pool.Exec(ctx, `UPDATE oidc_login_codes SET expires_at=clock_timestamp() WHERE code_hash=$1`, digest[:]); err != nil || changed.RowsAffected() != 1 {
		t.Fatal("could not expire the waiting code", err)
	}
	unlock()
	if err := <-released; !errors.Is(err, context.Canceled) {
		t.Fatal("fixture session lock did not roll back", err)
	}
	if !<-result {
		t.Fatal("expired exchange did not return invalid_grant without credentials")
	}
	var used, stored, audited int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM oidc_login_codes WHERE consumed_at IS NOT NULL),
		(SELECT count(*) FROM oidc_userinfo_tokens), (SELECT count(*) FROM audit_logs WHERE action='oidc.login.exchange')`).Scan(&used, &stored, &audited); err != nil || used+stored+audited != 0 {
		t.Fatal("expired exchange consumed the code or wrote a credential or success audit", err)
	}
}

func TestHumanOIDCRelyingPartyExchangeAndScopedUserInfo(t *testing.T) {
	rp := newHumanRP(t)
	ctx := oidc.ClientContext(t.Context(), rp.host.Client())
	for _, scope := range []string{"openid", "openid email", "openid profile", "openid email profile"} {
		t.Run(scope, func(t *testing.T) {
			code, verifier := rp.authorize(t, strings.Fields(scope)...)
			if _, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(oauth2.GenerateVerifier())); err == nil {
				t.Fatal("wrong verifier accepted")
			}
			wrong := rp.config
			wrong.RedirectURL += "/"
			if _, err := wrong.Exchange(ctx, code, oauth2.VerifierOption(verifier)); err == nil {
				t.Fatal("unregistered redirect accepted")
			}
			wrong = rp.config
			wrong.ClientSecret += "x"
			if _, err := wrong.Exchange(ctx, code, oauth2.VerifierOption(verifier)); err == nil {
				t.Fatal("wrong secret accepted")
			}
			wrong = rp.config
			wrong.ClientID += "/other"
			if _, err := wrong.Exchange(ctx, code, oauth2.VerifierOption(verifier)); err == nil {
				t.Fatal("code accepted for another client")
			}
			token, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
			if err != nil || token.AccessToken == "" || token.RefreshToken != "" || !token.Valid() {
				t.Fatal("RP code exchange failed")
			}
			raw, ok := token.Extra("id_token").(string)
			if !ok {
				t.Fatal("missing ID token")
			}
			id, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID, SupportedSigningAlgs: []string{oidc.ES256}}).Verify(ctx, raw)
			if err != nil || id.Nonce != "rp-test-nonce" || id.Subject != "usr_human_rp" {
				t.Fatal("independent ID verification failed")
			}
			info, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
			if err != nil || info.Subject != id.Subject {
				t.Fatal("UserInfo subject mismatch")
			}
			var claims map[string]any
			if err := info.Claims(&claims); err != nil {
				t.Fatal(err)
			}
			_, email := claims["email"]
			_, verified := claims["email_verified"]
			_, profile := claims["name"]
			if email != strings.Contains(scope, "email") || verified != email || profile != strings.Contains(scope, "profile") {
				t.Fatal("UserInfo did not respect the approved scope")
			}
			if _, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: raw})); err == nil {
				t.Fatal("UserInfo accepted an ID token")
			}
			if _, err := rp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier)); err == nil {
				t.Fatal("code replay accepted")
			}
			sum := sha256.Sum256([]byte(token.AccessToken))
			var stored int
			if err := rp.st.Pool.QueryRow(ctx, "SELECT count(*) FROM oidc_userinfo_tokens WHERE token_hash=$1", sum[:]).Scan(&stored); err != nil || stored != 1 {
				t.Fatal("missing hashed access token")
			}
		})
	}
}
