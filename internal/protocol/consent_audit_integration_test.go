package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/session"
)

type consentAuditFixture struct {
	redemptionFixture
	tokens            session.Tokens
	handle, requestID string
	userID            string
}

func newConsentAuditFixture(t *testing.T, unbound bool) consentAuditFixture {
	t.Helper()
	ctx := context.Background()
	f := consentAuditFixture{redemptionFixture: newRedemptionFixture(t), userID: "usr_redemption"}
	f.handler = route.Middleware(route.Principal, f.handler)
	f.sessions.HMACKeys = [][]byte{[]byte(strings.Repeat("s", 32))}
	f.sessions.Settings = func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: time.Hour}, nil
	}
	memberID := f.owner.ID
	if unbound {
		f.userID, memberID = "usr_consent_unbound", ""
		if _, err := f.store.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
			VALUES ($1, 'private-unbound@example.test', 'private-unbound@example.test', 'private-password-hash', 'active')`, f.userID); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.tokens, err = f.sessions.CreateForMember(ctx, f.userID, memberID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"response_type": {"code"}, "client_id": {"app_redemption"}, "redirect_uri": {"https://client.test/callback"},
		"scope": {"auth.members:read"}, "state": {"private-consent-state"}, "nonce": {"private-consent-nonce"},
		"code_challenge_method": {"S256"}, "code_challenge": {strings.Repeat("A", 43)}}
	start := httptest.NewRecorder()
	f.handler.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil))
	var request struct {
		RequestID string `json:"request_id"`
	}
	if start.Code != http.StatusOK || json.Unmarshal(start.Body.Bytes(), &request) != nil || request.RequestID == "" {
		t.Fatalf("authorization request failed: status=%d", start.Code)
	}
	f.handle = request.RequestID
	hash := sha256.Sum256([]byte(f.handle))
	if err := f.store.Pool.QueryRow(ctx, `SELECT id FROM oauth_authorization_requests WHERE request_hash = $1`, hash[:]).Scan(&f.requestID); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f consentAuditFixture) decide(t *testing.T, ctx context.Context, decision string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{"request_id": f.handle, "decision": decision}
	if decision == "approve" {
		body["member_id"], body["permissions"] = f.owner.ID, []string{"auth.members:read"}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(string(encoded))).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+f.tokens.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req_consent_audit")
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	return out
}

func (f consentAuditFixture) events(t *testing.T, memberID string) []audit.Event {
	t.Helper()
	page, err := f.applications.Authorization.ListAuditLogs(context.Background(), f.owner.ID,
		authorization.AuditQuery{SpaceID: f.owner.SpaceID, RequestID: "req_consent_audit", MemberID: memberID})
	if err != nil {
		t.Fatal(err)
	}
	var events []audit.Event
	for _, event := range page.Events {
		if strings.HasPrefix(event.Action, "oauth.consent.") {
			events = append(events, event)
		}
	}
	return events
}

func TestOAuthConsentAuditHTTPPreservesDecisionContext(t *testing.T) {
	t.Parallel()
	for _, scenario := range []struct {
		name, decision string
		unbound        bool
	}{{"approve", "approve", false}, {"deny", "deny", false}, {"unbound_account_denies", "deny", true}} {
		t.Run(scenario.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newConsentAuditFixture(t, scenario.unbound)
			var before string
			if scenario.decision == "deny" {
				if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM members),
				(SELECT count(*) FROM authorization_codes), (SELECT count(*) FROM authorization_grants),
				(SELECT policy_version FROM spaces WHERE id = $1))::text`, f.owner.SpaceID).Scan(&before); err != nil {
					t.Fatal(err)
				}
			}
			out := f.decide(t, ctx, scenario.decision)
			if out.Code != http.StatusOK {
				t.Fatalf("consent decision failed: status=%d", out.Code)
			}
			if scenario.decision == "deny" {
				var after string
				if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM members),
				(SELECT count(*) FROM authorization_codes), (SELECT count(*) FROM authorization_grants),
				(SELECT policy_version FROM spaces WHERE id = $1))::text`, f.owner.SpaceID).Scan(&after); err != nil || after != before {
					t.Fatal("denial created an Agent, code, grant, or authority change")
				}
			}
			events := f.events(t, "")
			if len(events) != 1 {
				t.Fatal("consent decision did not create one queryable audit")
			}
			event := events[0]
			var version int64
			if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, f.owner.SpaceID).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if event.Action != "oauth.consent."+scenario.decision || event.ActorType != "user" || event.ActorID != f.userID || event.UserID != f.userID ||
				event.ApplicationID != "app_redemption" || event.SpaceID != f.owner.SpaceID || event.Plane != "principal" ||
				event.CredentialType != "user_access_token" || event.RequestID != "req_consent_audit" || event.PolicyVersion != version || event.Outcome != "success" || event.PermissionKey != "" {
				t.Fatal("consent audit lost the authenticated account, client, request, or committed version")
			}
			var metadata map[string]any
			if json.Unmarshal(event.Metadata, &metadata) != nil || metadata["authorization_request_id"] != f.requestID || metadata["owner_chain_complete"] != true {
				t.Fatal("consent audit omitted its non-secret request reference")
			}
			filtered := f.events(t, f.owner.ID)
			if scenario.decision == "approve" {
				if event.MemberID != f.agent.ID || event.MemberType != "agent" || event.ResourceType != "member" || event.ResourceID != f.agent.ID ||
					event.ResourceGroupID != f.agent.HomeGroupID || len(event.OwnerChain) != 1 || event.OwnerChain[0].MemberID != f.owner.ID || metadata["owner_member_id"] != f.owner.ID || len(filtered) != 1 {
					t.Fatal("approval audit omitted the actual OAuth Agent and owner chain")
				}
				if err := f.agents.Delete(ctx, f.owner.ID, f.agent.ID); err != nil {
					t.Fatal(err)
				}
				if after := f.events(t, f.owner.ID); !cmp.Equal(after, events) {
					t.Fatal("OAuth Agent tombstone changed consent history")
				}
			} else if event.MemberID != "" || event.MemberType != "" || len(event.OwnerChain) != 0 || event.ResourceType != "application" ||
				event.ResourceID != "app_redemption" || event.ResourceGroupID != "" || metadata["subject_selection"] != "none" || len(filtered) != 0 {
				t.Fatal("denial invented a selected member or Agent")
			}
			encoded, err := json.Marshal(events)
			if err != nil {
				t.Fatal(err)
			}
			var redirect struct {
				RedirectTo string `json:"redirect_to"`
			}
			if json.Unmarshal(out.Body.Bytes(), &redirect) != nil {
				t.Fatal("invalid consent redirect")
			}
			callback, err := url.Parse(redirect.RedirectTo)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{f.handle, f.tokens.AccessToken, f.tokens.RefreshToken, f.code, f.refresh, f.verifier,
				"private-consent-state", "private-consent-nonce", "private-unbound@example.test", "redemption@example.test", callback.Query().Get("code")} {
				if private != "" && strings.Contains(string(encoded), private) {
					t.Fatal("consent audit leaked a credential or private protocol value")
				}
			}
			other, otherActor, err := f.applications.Authorization.CreateSpace(ctx, "usr_redemption", "Other customer", "other-consent-customer")
			if err != nil {
				t.Fatal(err)
			}
			page, err := f.applications.Authorization.ListAuditLogs(ctx, otherActor.ID, authorization.AuditQuery{SpaceID: other.ID, RequestID: "req_consent_audit"})
			if err != nil || len(page.Events) != 0 {
				t.Fatal("consent audit leaked into another Space")
			}
		})
	}
}

func (f consentAuditFixture) state(t *testing.T) string {
	t.Helper()
	var value string
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT jsonb_build_array(
		(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM members m), (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM groups g),
		(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM authorization_grants g), (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM assign_rights r),
		(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM spaces s), (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM oauth_authorization_requests r),
		(SELECT count(*) FROM authorization_codes), (SELECT count(*) FROM agent_credentials), (SELECT count(*) FROM audit_logs))::text`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestOAuthConsentAuditHTTPFailureRollsBackDecision(t *testing.T) {
	t.Parallel()
	for _, decision := range []string{"approve", "deny"} {
		t.Run(decision, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newConsentAuditFixture(t, false)
			if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_consent_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN IF NEW.action = 'oauth.consent.`+decision+`' THEN RAISE EXCEPTION 'injected consent audit failure'; END IF; RETURN NEW; END $$;
			CREATE TRIGGER reject_consent_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_consent_audit()`); err != nil {
				t.Fatal(err)
			}
			before := f.state(t)
			out := f.decide(t, ctx, decision)
			if out.Code != http.StatusServiceUnavailable || f.state(t) != before || strings.Contains(out.Body.String(), "redirect_to") {
				t.Fatal("failed audit retained a decision, Agent, grant, code, policy change, or callback")
			}
			if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_consent_audit ON audit_logs`); err != nil {
				t.Fatal(err)
			}
			if retry := f.decide(t, ctx, decision); retry.Code != http.StatusOK || len(f.events(t, "")) != 1 {
				t.Fatal("original consent request could not retry exactly once after audit recovery")
			}
			if replay := f.decide(t, ctx, decision); replay.Code != http.StatusBadRequest || len(f.events(t, "")) != 1 {
				t.Fatal("consumed consent request was replayed")
			}
		})
	}
}

func TestOAuthConsentApproveAndDenyRaceCommitsOneDecision(t *testing.T) {
	t.Parallel()
	f := newConsentAuditFixture(t, false)
	responses := make(chan *httptest.ResponseRecorder, 2)
	for _, decision := range []string{"approve", "deny"} {
		go func() { responses <- f.decide(t, context.Background(), decision) }()
	}
	var successes, failures int
	for range 2 {
		switch out := <-responses; out.Code {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
			failures++
		default:
			t.Fatalf("unexpected concurrent consent status=%d", out.Code)
		}
	}
	events := f.events(t, "")
	if successes != 1 || failures != 1 || len(events) != 1 {
		t.Fatal("concurrent approve and deny did not commit one decision")
	}
	var status string
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT status FROM oauth_authorization_requests WHERE id = $1`, f.requestID).Scan(&status); err != nil ||
		(status == "approved" && events[0].Action != "oauth.consent.approve") || (status == "denied" && events[0].Action != "oauth.consent.deny") || (status != "approved" && status != "denied") {
		t.Fatal("persisted consent status disagrees with its audit")
	}
}

func TestOAuthConsentHTTPRechecksIdentityClientAndExpiryAfterWaiting(t *testing.T) {
	t.Parallel()
	for _, decision := range []string{"approve", "deny"} {
		for _, change := range []string{"account", "client", "session_revoked", "bearer_binding", "access_expiry", "session_expiry", "access_expiry_at_resource_lock", "session_expiry_at_resource_lock", "selected_binding_expiry", "expiry_at_request_lock", "expiry_at_client_lock"} {
			if decision == "deny" && change == "selected_binding_expiry" {
				continue
			}
			t.Run(decision+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				f := newConsentAuditFixture(t, false)
				if change == "selected_binding_expiry" {
					var err error
					f.tokens, err = f.sessions.CreateForMember(ctx, f.userID, "", nil, "test", 1)
					if err != nil {
						t.Fatal(err)
					}
				}
				expiresAt := time.Now().UTC().Add(2 * time.Second)
				if strings.HasPrefix(change, "expiry_") {
					if _, err := f.store.Pool.Exec(ctx, `UPDATE oauth_authorization_requests SET expires_at = $2 WHERE id = $1`, f.requestID, expiresAt); err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasPrefix(change, "access_expiry") {
					claims, err := f.sessions.VerifyAccess(f.tokens.AccessToken)
					if err != nil {
						t.Fatal(err)
					}
					claims.ExpiresAt = expiresAt.Unix()
					f.tokens.AccessToken, err = f.sessions.Signer.Sign(claims)
					if err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasPrefix(change, "session_expiry") {
					if _, err := f.store.Pool.Exec(ctx, `UPDATE sessions SET expires_at = $2 WHERE id = $1`, f.tokens.SessionID, expiresAt); err != nil {
						t.Fatal(err)
					}
				}
				if change == "selected_binding_expiry" {
					if _, err := f.store.Pool.Exec(ctx, `UPDATE user_members SET expires_at = $3 WHERE user_id = $1 AND member_id = $2`, f.userID, f.owner.ID, expiresAt); err != nil {
						t.Fatal(err)
					}
				}
				barrier, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = barrier.Rollback(context.Background()) })
				if err := f.store.InTx(barrier.Context(ctx), func(q *db.Queries) error {
					switch change {
					case "account":
						return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: f.userID, Status: "disabled"})
					case "client":
						return q.SuspendApplicationGlobally(ctx, db.SuspendApplicationGloballyParams{ApplicationID: "app_redemption"})
					case "session_revoked":
						return q.RevokeSession(ctx, db.RevokeSessionParams{ID: f.tokens.SessionID})
					case "bearer_binding":
						if _, err := q.LockMemberForAuthorization(ctx, db.LockMemberForAuthorizationParams{ID: f.owner.ID}); err != nil {
							return err
						}
						return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: f.userID, MemberID: f.owner.ID})
					case "expiry_at_request_lock":
						hash := sha256.Sum256([]byte(f.handle))
						_, err := q.LockOAuthAuthorizationRequest(ctx, db.LockOAuthAuthorizationRequestParams{RequestHash: hash[:]})
						return err
					case "access_expiry_at_resource_lock", "session_expiry_at_resource_lock", "selected_binding_expiry":
						_, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: f.owner.SpaceID})
						return err
					default:
						_, err := f.applications.OAuthClientByIDTx(ctx, q, "app_redemption")
						return err
					}
				}); err != nil {
					t.Fatal(err)
				}
				before := f.state(t)
				response := make(chan *httptest.ResponseRecorder, 1)
				go func() { response <- f.decide(t, ctx, decision) }()
				for {
					var waiting bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case out := <-response:
						t.Fatalf("consent skipped its identity or expiry lock: status=%d", out.Code)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				if strings.Contains(change, "expiry") {
					timer := time.NewTimer(time.Until(expiresAt.Add(25 * time.Millisecond)))
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				if err := barrier.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case out := <-response:
					status, code := http.StatusBadRequest, "invalid_request"
					if change == "account" || change == "session_revoked" || change == "bearer_binding" || strings.HasPrefix(change, "access_expiry") || strings.HasPrefix(change, "session_expiry") {
						status, code = http.StatusUnauthorized, "invalid_token"
					}
					if out.Code != status || !strings.Contains(out.Body.String(), code) || strings.Contains(out.Body.String(), "redirect_to") || f.state(t) != before {
						t.Fatalf("consent ignored committed %s change: status=%d", change, out.Code)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			})
		}
	}
}

func TestOAuthConsentHTTPKeepsIdentityAndClientLocksUntilCommit(t *testing.T) {
	t.Parallel()
	for _, decision := range []string{"approve", "deny"} {
		for _, change := range []string{"account", "client", "session", "bearer_binding"} {
			t.Run(decision+"/"+change, func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				f := newConsentAuditFixture(t, false)
				mutation, err := f.store.BeginIdempotency(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
				if out := f.decide(t, mutation.Context(ctx), decision); out.Code != http.StatusOK {
					t.Fatalf("consent failed before commit barrier: status=%d", out.Code)
				}
				changed := make(chan error, 1)
				go func() {
					changed <- f.store.InTx(ctx, func(q *db.Queries) error {
						switch change {
						case "account":
							return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: f.userID, Status: "disabled"})
						case "session":
							return q.RevokeSession(ctx, db.RevokeSessionParams{ID: f.tokens.SessionID})
						case "bearer_binding":
							if _, err := q.LockMemberForAuthorization(ctx, db.LockMemberForAuthorizationParams{ID: f.owner.ID}); err != nil {
								return err
							}
							return q.RevokeUserMember(ctx, db.RevokeUserMemberParams{UserID: f.userID, MemberID: f.owner.ID})
						default:
							return q.SuspendApplicationGlobally(ctx, db.SuspendApplicationGloballyParams{ApplicationID: "app_redemption"})
						}
					})
				}()
				for {
					var waiting bool
					if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
					select {
					case err := <-changed:
						t.Fatalf("identity change bypassed consent transaction: %v", err)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				if err := mutation.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-changed:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				var events int
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE request_id = 'req_consent_audit' AND action = $1`, "oauth.consent."+decision).Scan(&events); err != nil || events != 1 {
					t.Fatal("serialized identity change lost the committed consent audit")
				}
			})
		}
	}
}
