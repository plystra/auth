package protocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
)

type oidcConsentFixture struct {
	consentAuditFixture
	server *httptest.Server
}

func newOIDCConsentFixture(t *testing.T) oidcConsentFixture {
	t.Helper()
	base := newConsentAuditFixture(t, true)
	if _, err := base.store.Pool.Exec(t.Context(), `UPDATE applications SET human_oidc_enabled=true WHERE id='app_redemption'`); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(base.handler)
	t.Cleanup(server.Close)
	return oidcConsentFixture{base, server}
}

func (f oidcConsentFixture) query() url.Values {
	digest := sha256.Sum256([]byte(f.verifier))
	return url.Values{
		"response_type": {"code"}, "client_id": {"app_redemption"}, "redirect_uri": {"https://client.test/callback"},
		"scope": {"openid email profile"}, "state": {"rp-preserved-state"}, "nonce": {"rp-preserved-nonce"},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])},
	}
}

func (f oidcConsentFixture) start(t *testing.T, q url.Values, wantStatus int) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/oauth/authorize?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if wantStatus == http.StatusOK {
		if err := f.store.Pool.QueryRow(t.Context(), "SELECT clock_timestamp()").Scan(&before); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		RequestID string    `json:"request_id"`
		ExpiresAt time.Time `json:"expires_at"`
		Scopes    []string  `json:"scopes"`
	}
	if resp.StatusCode != wantStatus || resp.Header.Get("Location") != "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("sign-in request status=%d, want %d; location or cache headers incorrect", resp.StatusCode, wantStatus)
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if wantStatus == http.StatusOK {
		if !strings.HasPrefix(body.RequestID, "olr_") || !slices.Equal(body.Scopes, strings.Fields(q.Get("scope"))) {
			t.Fatal("login request metadata did not bind the expected type or scope")
		}
		digest := sha256.Sum256([]byte(body.RequestID))
		var stored, after time.Time
		if err := f.store.Pool.QueryRow(t.Context(), "SELECT expires_at, clock_timestamp() FROM oidc_login_requests WHERE request_hash=$1", digest[:]).Scan(&stored, &after); err != nil {
			t.Fatal(err)
		}
		if !body.ExpiresAt.Equal(stored) || stored.Before(before.Add(5*time.Minute)) || stored.After(after.Add(5*time.Minute)) {
			t.Fatal("login request expiry does not match the stored five-minute lifetime")
		}
	} else if body.RequestID != "" {
		t.Fatal("rejected input issued an authorization request")
	}
	return body.RequestID
}

func (f oidcConsentFixture) post(ctx context.Context, token string, body map[string]any) (int, *url.URL, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.server.URL+"/oauth/authorize", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := f.server.Client().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return resp.StatusCode, nil, err
	}
	redirect, err := url.Parse(out.RedirectTo)
	return resp.StatusCode, redirect, err
}

func (f oidcConsentFixture) decision(t *testing.T, handle, decision string, extra map[string]any, want int) url.Values {
	t.Helper()
	body := map[string]any{"request_id": handle, "decision": decision}
	for key, value := range extra {
		body[key] = value
	}
	status, redirect, err := f.post(t.Context(), f.tokens.AccessToken, body)
	if err != nil || status != want {
		t.Fatalf("consent HTTP status=%d, want %d, transport error=%v", status, want, err)
	}
	if want != http.StatusOK {
		if redirect.String() != "" {
			t.Fatal("invalid decision produced a redirect")
		}
		return nil
	}
	if redirect.Scheme != "https" || redirect.Host != "client.test" || redirect.Path != "/callback" || redirect.Query().Get("state") != f.query().Get("state") {
		t.Fatal("consent callback lost exact target or state")
	}
	return redirect.Query()
}

func TestHumanOIDCConsentBindsUnboundAccountSessionAndNeverCreatesDelegation(t *testing.T) {
	f := newOIDCConsentFixture(t)
	ctx := t.Context()
	snapshot := func() [5]int {
		t.Helper()
		var out [5]int
		if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM application_installations),
            (SELECT count(*) FROM members), (SELECT count(*) FROM authorization_grants),
            (SELECT count(*) FROM roles), (SELECT count(*) FROM authorization_codes)`).Scan(&out[0], &out[1], &out[2], &out[3], &out[4]); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	query := f.query()
	handle := f.start(t, query, http.StatusOK)
	for _, extra := range []map[string]any{
		{"member_id": f.owner.ID}, {"permissions": []string{}}, {"user_id": "usr_redemption"}, {"scopes": []string{"openid"}}, {"redirect_uri": "https://elsewhere.test"},
	} {
		f.decision(t, handle, "approve", extra, http.StatusBadRequest)
	}
	params := f.decision(t, handle, "approve", nil, http.StatusOK)
	code := params.Get("code")
	if !strings.HasPrefix(code, "olc_") || params.Has("error") {
		t.Fatal("expected an opaque human login code")
	}
	codeHash := sha256.Sum256([]byte(code))
	handleHash := sha256.Sum256([]byte(handle))
	claims, err := f.sessions.VerifyAccess(t.Context(), f.tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	var binding, metadata bool
	err = f.store.Pool.QueryRow(ctx, `SELECT c.user_id=$3 AND c.session_id=$4 AND s.user_id=$3 AND c.application_id='app_redemption'
          AND c.scope=$5 AND c.nonce=$6 AND c.code_challenge=$7 AND c.redirect_uri=$8 AND c.application_generation=a.human_oidc_generation
          AND c.expires_at-c.created_at BETWEEN interval '119 seconds' AND interval '121 seconds'
          AND r.status='approved' AND r.consumed_at IS NOT NULL AND r.application_generation=c.application_generation,
          EXISTS(SELECT 1 FROM audit_logs e WHERE e.action='oidc.consent.approve' AND e.user_id=c.user_id
          AND e.application_id=c.application_id AND e.metadata->>'authorization_request_id'=r.id
          AND e.metadata->>'scope'=c.scope AND e.member_id IS NULL
          AND e.metadata::text NOT LIKE '%' || $9 || '%' AND e.metadata::text NOT LIKE '%' || $10 || '%')
        FROM oidc_login_codes c JOIN oidc_login_requests r ON r.id=c.request_id JOIN sessions s ON s.id=c.session_id
        JOIN applications a ON a.id=c.application_id WHERE c.code_hash=$1 AND r.request_hash=$2`, codeHash[:], handleHash[:], f.userID,
		claims.SessionID, query.Get("scope"), query.Get("nonce"), query.Get("code_challenge"), query.Get("redirect_uri"), handle, code).Scan(&binding, &metadata)
	if err != nil || !binding || !metadata {
		t.Fatalf("session/code/audit binding=%v metadata=%v error=%v", binding, metadata, err)
	}
	f.decision(t, handle, "approve", nil, http.StatusBadRequest)
	deniedHandle := f.start(t, query, http.StatusOK)
	denied := f.decision(t, deniedHandle, "deny", nil, http.StatusOK)
	if denied.Get("error") != "access_denied" || denied.Has("code") {
		t.Fatal("denial response is invalid")
	}
	f.decision(t, deniedHandle, "approve", nil, http.StatusBadRequest)
	var codes, denials int
	if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM oidc_login_codes),
        (SELECT count(*) FROM audit_logs WHERE action='oidc.consent.deny' AND user_id=$1)`, f.userID).Scan(&codes, &denials); err != nil || codes != 1 || denials != 1 || before != snapshot() {
		t.Fatal("login/denial affected delegation or produced extra credentials", err)
	}
}

func TestHumanOIDCConsentDisplaysClientIdentityFromRequestCreation(t *testing.T) {
	f := newOIDCConsentFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const updatedName = "Renamed relying party"
	edit, err := f.store.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = edit.Rollback(context.Background()) }()
	if err := f.store.InTx(edit.Context(ctx), func(q *db.Queries) error {
		tx, _ := q.Transaction()
		_, err := tx.Exec(ctx, "UPDATE applications SET name=$1 WHERE id='app_redemption'", updatedName)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	query := f.query()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		f.handler.ServeHTTP(response, req)
		done <- response
	}()
	waitForRedemptionLock(t, ctx, f.store, done)
	if err := edit.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	res := <-done
	var summary struct {
		Handle      string    `json:"request_id"`
		ExpiresAt   time.Time `json:"expires_at"`
		ClientID    string    `json:"client_id"`
		ClientName  string    `json:"client_name"`
		RedirectURI string    `json:"redirect_uri"`
		Scopes      []string  `json:"scopes"`
	}
	decoder := json.NewDecoder(res.Body)
	decoder.DisallowUnknownFields()
	if res.Code != http.StatusOK || decoder.Decode(&summary) != nil {
		t.Fatalf("expected the OIDC disclosure response, status=%d", res.Code)
	}
	if summary.ClientName != updatedName || summary.ClientID != query.Get("client_id") || summary.RedirectURI != query.Get("redirect_uri") ||
		!slices.Equal(summary.Scopes, strings.Fields(query.Get("scope"))) || !summary.ExpiresAt.After(time.Now()) {
		t.Fatal("consent display did not match the client metadata when the request was created")
	}
	if code := f.decision(t, summary.Handle, "approve", nil, http.StatusOK).Get("code"); code == "" {
		t.Fatal("confirmed disclosure did not issue an authorization code")
	}
}

func TestAuthorizationRejectsMalformedScopeBeforeCreatingConsentRequests(t *testing.T) {
	f := newOIDCConsentFixture(t)
	request := func(scope string) *httptest.ResponseRecorder {
		q := f.query()
		q.Set("scope", scope)
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
		return res
	}
	requests := func() [2]int {
		t.Helper()
		var counts [2]int
		if err := f.store.Pool.QueryRow(t.Context(), "SELECT (SELECT count(*) FROM oidc_login_requests), (SELECT count(*) FROM oauth_authorization_requests)").Scan(&counts[0], &counts[1]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	before := requests()
	for _, scope := range []string{"", "openid\temail", "openid\nprofile", "openid\u00a0email", "openid  email",
		" openid", "openid ", "auth.members:read\tauth.members:read", "open\"id", "open\\id", "openid\x7f", "openid\xff"} {
		res := request(scope)
		var denied struct {
			Error     struct{ Code string }
			RequestID string `json:"request_id"`
		}
		if res.Code != http.StatusBadRequest || json.NewDecoder(res.Body).Decode(&denied) != nil ||
			denied.Error.Code != "invalid_scope" || denied.RequestID != "" || res.Header().Get("Location") != "" {
			t.Errorf("invalid scope %q was not rejected locally: status=%d", scope, res.Code)
		}
	}
	if requests() != before {
		t.Fatal("malformed scope created a pending authorization request")
	}
	for _, tc := range []struct {
		scope string
		field string
		want  []string
	}{
		{"openid email openid", "scopes", []string{"openid", "email"}},
		{"auth.members:read auth.members:read", "permissions", []string{"auth.members:read"}},
	} {
		res := request(tc.scope)
		var body map[string]json.RawMessage
		var got []string
		if res.Code != http.StatusOK || json.NewDecoder(res.Body).Decode(&body) != nil ||
			json.Unmarshal(body[tc.field], &got) != nil || !slices.Equal(got, tc.want) {
			t.Fatalf("valid scope %q did not return its requested disclosure", tc.scope)
		}
	}
}

func TestHumanOIDCRequestsRejectMixedScopesAndStaleConfiguration(t *testing.T) {
	f := newOIDCConsentFixture(t)
	for _, change := range []struct{ key, value string }{
		{"scope", "openid auth.members:read"}, {"scope", "openid offline_access"}, {"resource", "app_redemption"},
		{"redirect_uri", "https://client.test/callback/"}, {"nonce", ""}, {"state", ""}, {"code_challenge_method", "plain"},
		{"code_challenge", "invalid"},
	} {
		q := f.query()
		q.Set(change.key, change.value)
		f.start(t, q, http.StatusBadRequest)
	}
	q := f.query()
	q.Add("scope", "auth.members:read")
	f.start(t, q, http.StatusBadRequest)
	for _, mutations := range [][2]string{
		{"human_oidc_enabled=false", "human_oidc_enabled=true"}, {"status='suspended'", "status='active'"},
		{"redirect_uris='[]'", "redirect_uris='[\"https://client.test/callback\"]'"},
	} {
		handle := f.start(t, f.query(), http.StatusOK)
		for i, assignment := range mutations {
			if _, err := f.store.Pool.Exec(t.Context(), "UPDATE applications SET "+assignment+" WHERE id='app_redemption'"); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				f.start(t, f.query(), http.StatusBadRequest)
			}
		}
		f.decision(t, handle, "approve", nil, http.StatusBadRequest)
		f.decision(t, handle, "deny", nil, http.StatusBadRequest)
	}
	handle := f.start(t, f.query(), http.StatusOK)
	if _, err := f.store.Pool.Exec(t.Context(), `UPDATE oidc_login_requests SET expires_at=clock_timestamp()-interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	f.decision(t, handle, "approve", nil, http.StatusBadRequest)
}

func TestHumanOIDCConsentConsumesOnceAndRollsBackFailedAudit(t *testing.T) {
	f := newOIDCConsentFixture(t)
	ctx := t.Context()
	handle := f.start(t, f.query(), http.StatusOK)
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_login_consent() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action LIKE 'oidc.consent.%' THEN RAISE EXCEPTION 'unavailable'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_login_consent BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_login_consent()`); err != nil {
		t.Fatal(err)
	}
	f.decision(t, handle, "approve", nil, http.StatusServiceUnavailable)
	f.decision(t, handle, "deny", nil, http.StatusServiceUnavailable)
	if _, err := f.store.Pool.Exec(ctx, `ALTER TABLE audit_logs DISABLE TRIGGER reject_login_consent`); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"request_id": handle, "decision": "approve"}
	results := make(chan int, 2)
	for range 2 {
		go func() {
			status, _, err := f.post(ctx, f.tokens.AccessToken, body)
			if err != nil {
				status = 0
			}
			results <- status
		}()
	}
	statuses := []int{<-results, <-results}
	slices.Sort(statuses)
	var codes, events int
	if err := f.store.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM oidc_login_codes),
        (SELECT count(*) FROM audit_logs WHERE action LIKE 'oidc.consent.%')`).Scan(&codes, &events); err != nil ||
		!slices.Equal(statuses, []int{http.StatusOK, http.StatusBadRequest}) || codes != 1 || events != 1 {
		t.Fatalf("decisions=%v codes=%d events=%d error=%v", statuses, codes, events, err)
	}
}

func TestHumanOIDCConsentRequiresLiveHumanSessionAtDecision(t *testing.T) {
	f := newOIDCConsentFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	handle := f.start(t, f.query(), http.StatusOK)
	body := map[string]any{"request_id": handle, "decision": "approve"}
	agentToken, err := f.sessions.CreateAgentAccess(ctx, f.agent.ID, f.owner.SpaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"", agentToken.AccessToken} {
		status, redirect, err := f.post(ctx, credential, body)
		if err != nil || status != http.StatusUnauthorized || redirect.String() != "" {
			t.Fatalf("login consent accepted a non-user credential; status=%d error=%v", status, err)
		}
	}
	barrier, err := f.store.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = barrier.Rollback(context.Background()) }()
	if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
		return q.RevokeSession(ctx, db.RevokeSessionParams{ID: f.tokens.SessionID})
	}); err != nil {
		t.Fatal(err)
	}
	result := make(chan int, 1)
	go func() { status, _, _ := f.post(ctx, f.tokens.AccessToken, body); result <- status }()
	for {
		var waiting bool
		if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%LockSessionForStepUp%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case status := <-result:
			t.Fatalf("consent skipped the session write lock; status=%d", status)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := barrier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != http.StatusUnauthorized {
		t.Fatalf("consent with revoked session status=%d", status)
	}
	f.tokens, err = f.sessions.CreateForMember(ctx, f.userID, "", nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	f.decision(t, handle, "approve", nil, http.StatusOK)
}
