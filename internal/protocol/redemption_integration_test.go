package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type redemptionFixture struct {
	store        *store.Store
	sessions     *session.Service
	agents       *agent.Service
	applications *application.Service
	owner        authorization.Member
	agent        agent.Agent
	handler      http.Handler
	code         string
	refresh      string
	verifier     string
}

func newRedemptionFixture(t *testing.T) redemptionFixture {
	t.Helper()
	ctx := context.Background()
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
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_redemption', 'redemption@example.test', 'redemption@example.test', 'test-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	_, owner, err := authz.CreateSpace(ctx, "usr_redemption", "Redemption", "redemption")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO applications
		(id, space_id, name, client_id, redirect_uris, allowed_scopes, manifest_permissions)
		VALUES ('app_redemption', $1, 'Redemption', 'app_redemption', '["https://client.test/callback"]',
		'["auth.members:read"]', '["auth.members:read"]')`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO members (id, space_id, name, type, binding_policy, status)
		VALUES ('mem_redemption_installation', $1, 'Installation', 'application', 'single', 'active')`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO roles (id, space_id, name, managed)
		VALUES ('rol_redemption', $1, 'application:ins_redemption', true)`, owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO application_installations
		(id, application_id, space_id, member_id, role_id, scope, approved_permissions, installed_by)
		VALUES ('ins_redemption', 'app_redemption', $1, 'mem_redemption_installation', 'rol_redemption',
		'space', '["auth.members:read"]', $2)`, owner.SpaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("r", 32))}}
	ag, err := agents.CreateOAuth(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_redemption",
		Name: "OAuth Agent", OAuthClientID: "app_redemption", Source: "oauth", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := agents.CreateOAuthRefreshCredential(ctx, ag.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("c", 32))}}
	code, verifier := "test-authorization-code-with-sufficient-entropy", strings.Repeat("v", 43)
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{Store: st, Signer: signer, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute}, nil
	}}
	var mux http.ServeMux
	(HTTP{Issuer: signer.Issuer(), Agents: agents, Applications: apps, Sessions: sessions, Authorization: authz}).Register(&mux)
	f := redemptionFixture{store: st, sessions: sessions, agents: agents, applications: apps, owner: owner, agent: ag,
		handler: &mux, code: code, refresh: refresh, verifier: verifier}
	f.issueCode(t, "cod_redemption")
	return f
}

func (f redemptionFixture) issueCode(t *testing.T, id string) {
	t.Helper()
	hash, challenge := sha256.Sum256([]byte(f.code)), sha256.Sum256([]byte(f.verifier))
	if err := f.applications.CreateAuthorizationCode(context.Background(), application.CreateAuthorizationCodeInput{
		ID: id, ApplicationID: "app_redemption", UserID: "usr_redemption", MemberID: f.agent.ID,
		CodeHash: hash[:], RedirectURI: "https://client.test/callback", Scope: "auth.members:read",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256",
		Resource: "app_redemption", ExpiresAt: time.Now().Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
}

func (f redemptionFixture) form(grant string) url.Values {
	if grant == "authorization_code" {
		return url.Values{"grant_type": {grant}, "client_id": {"app_redemption"}, "code": {f.code},
			"code_verifier": {f.verifier}, "redirect_uri": {"https://client.test/callback"}}
	}
	return url.Values{"grant_type": {grant}, "client_id": {"app_redemption"}, "refresh_token": {f.refresh}}
}

func (f redemptionFixture) request(ctx context.Context, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode())).WithContext(ctx)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func (f redemptionFixture) assertUnchanged(t *testing.T) {
	t.Helper()
	var consumed, used, credentials, events int
	err := f.store.Pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM authorization_codes WHERE consumed_at IS NOT NULL),
		(SELECT count(*) FROM agent_credentials WHERE last_used_at IS NOT NULL),
		(SELECT count(*) FROM agent_credentials),
		(SELECT count(*) FROM audit_logs WHERE action IN ('agent.access.issue', 'agent.oauth_refresh', 'agent.oauth_refresh.create'))`).
		Scan(&consumed, &used, &credentials, &events)
	if err != nil || consumed != 0 || used != 0 || credentials != 1 || events != 1 {
		t.Fatalf("failed redemption changed persistent state: consumed=%d used=%d credentials=%d events=%d error=%v", consumed, used, credentials, events, err)
	}
}

func TestOAuthRedemptionFailureRollsBackAndAllowsRetry(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, failure := range []string{"session_settings", "issuance_audit", "credential_audit", "commit"} {
			t.Run(grant+"/"+failure, func(t *testing.T) {
				f := newRedemptionFixture(t)
				ctx := context.Background()
				var restore func()
				if failure == "session_settings" {
					settings := f.sessions.Settings
					f.sessions.Settings = func(context.Context) (session.Settings, error) {
						return session.Settings{}, errors.New("settings unavailable")
					}
					restore = func() { f.sessions.Settings = settings }
				} else {
					action := "agent.access.issue"
					if failure == "credential_audit" {
						action = "agent.oauth_refresh"
						if grant == "authorization_code" {
							action = "agent.oauth_refresh.create"
						}
					}
					if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_redemption_audit() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN IF NEW.action = '`+action+`' THEN RAISE EXCEPTION 'redemption audit rejected'; END IF; RETURN NEW; END; $$`); err != nil {
						t.Fatal(err)
					}
					trigger := `CREATE TRIGGER reject_redemption_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_redemption_audit()`
					if failure == "commit" {
						trigger = `CREATE CONSTRAINT TRIGGER reject_redemption_audit AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_redemption_audit()`
					}
					if _, err := f.store.Pool.Exec(ctx, trigger); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_redemption_audit ON audit_logs`); err != nil {
							t.Fatal(err)
						}
					}
				}
				response := f.request(ctx, f.form(grant))
				if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "temporarily_unavailable") || strings.Contains(response.Body.String(), "access_token") {
					t.Fatalf("failed redemption response: status=%d", response.Code)
				}
				f.assertUnchanged(t)
				restore()
				delegationAuditToken(t, f.request(ctx, f.form(grant)))
			})
		}
	}
}

func TestOAuthCodeValidationFailureDoesNotConsumeCode(t *testing.T) {
	for _, field := range []string{"code_verifier", "resource", "redirect_uri"} {
		t.Run(field, func(t *testing.T) {
			f := newRedemptionFixture(t)
			form := f.form("authorization_code")
			form.Set(field, "incorrect")
			if response := f.request(context.Background(), form); response.Code != http.StatusBadRequest {
				t.Fatalf("invalid %s was accepted: status=%d", field, response.Code)
			}
			f.assertUnchanged(t)
			delegationAuditToken(t, f.request(context.Background(), f.form("authorization_code")))
		})
	}
}

func TestOAuthRefreshReplayCommitsFamilyRevocation(t *testing.T) {
	f := newRedemptionFixture(t)
	ctx := context.Background()
	first := f.request(ctx, f.form("refresh_token"))
	delegationAuditToken(t, first)
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil || body.RefreshToken == "" {
		t.Fatal("refresh response omitted successor")
	}
	if replay := f.request(ctx, f.form("refresh_token")); replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d", replay.Code)
	}
	form := f.form("refresh_token")
	form.Set("refresh_token", body.RefreshToken)
	if next := f.request(ctx, form); next.Code != http.StatusBadRequest {
		t.Fatalf("successor survived family replay: status=%d", next.Code)
	}
	var live, events int
	if err := f.store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_credentials WHERE revoked_at IS NULL),
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth_refresh.replay')`).Scan(&live, &events); err != nil || live != 0 || events != 1 {
		t.Fatalf("replay protection was not committed: live=%d events=%d error=%v", live, events, err)
	}
}

func TestOAuthRedemptionRevalidatesAfterConcurrentChanges(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, change := range []string{"client_rotation", "installation_suspend", "owner_suspend", "code_expiry"} {
			if change == "code_expiry" && grant != "authorization_code" {
				continue
			}
			t.Run(grant+"/"+change, func(t *testing.T) {
				f := newRedemptionFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				locked, release := make(chan struct{}), make(chan struct{})
				writer := make(chan error, 1)
				go func() {
					writer <- f.store.InTx(ctx, func(q *db.Queries) error {
						if change == "owner_suspend" {
							if err := member.LockChainsTx(ctx, q, f.owner.ID); err != nil {
								return err
							}
						} else if _, err := q.LockApplicationForUpdate(ctx, db.LockApplicationForUpdateParams{ApplicationID: "app_redemption"}); err != nil {
							return err
						}
						close(locked)
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
						tx, _ := q.Transaction()
						switch change {
						case "client_rotation":
							_, err := tx.Exec(ctx, `UPDATE applications SET client_secret_hash = $1 WHERE id = 'app_redemption'`,
								application.HMACClientSecretHash([]byte(strings.Repeat("c", 32)), "rotated-client-secret"))
							return err
						case "installation_suspend":
							if _, err := q.SetInstallationLifecycleStatus(ctx, db.SetInstallationLifecycleStatusParams{
								InstallationID: "ins_redemption", PreviousStatus: "active", NewStatus: "suspended",
							}); err != nil {
								return err
							}
							_, err := q.SetInstallationMemberStatus(ctx, db.SetInstallationMemberStatusParams{MemberID: "mem_redemption_installation", NewStatus: "suspended"})
							return err
						case "owner_suspend":
							return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.owner.ID, SpaceID: f.owner.SpaceID, Status: "suspended"})
						default:
							_, err := tx.Exec(ctx, `UPDATE authorization_codes SET expires_at = clock_timestamp() WHERE id = 'cod_redemption'`)
							return err
						}
					})
				}()
				select {
				case <-locked:
				case err := <-writer:
					t.Fatalf("could not establish mutation barrier: %v", err)
				}
				response := make(chan *httptest.ResponseRecorder, 1)
				go func() { response <- f.request(ctx, f.form(grant)) }()
				waitForRedemptionLock(t, ctx, f.store, response)
				close(release)
				if err := <-writer; err != nil {
					t.Fatal(err)
				}
				out := <-response
				want, code := http.StatusBadRequest, "invalid_grant"
				if change == "client_rotation" {
					want, code = http.StatusUnauthorized, "invalid_client"
				}
				if change == "owner_suspend" {
					want, code = http.StatusForbidden, "OWNER_INACTIVE"
				}
				if out.Code != want || !strings.Contains(out.Body.String(), code) || strings.Contains(out.Body.String(), "access_token") {
					t.Fatalf("redemption ignored committed %s: status=%d", change, out.Code)
				}
				f.assertUnchanged(t)
			})
		}
	}
}

func waitForRedemptionLock(t *testing.T, ctx context.Context, st *store.Store, response <-chan *httptest.ResponseRecorder) {
	t.Helper()
	for {
		var waiting bool
		if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
			AND wait_event_type = 'Lock' AND (query LIKE '%applications%FOR UPDATE%' OR query LIKE '%members%FOR UPDATE%'))`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case out := <-response:
			t.Fatalf("redemption bypassed its mutation lock: status=%d", out.Code)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestOAuthConcurrentRedemptionIsSingleUse(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		t.Run(grant, func(t *testing.T) {
			f := newRedemptionFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			responses := make(chan *httptest.ResponseRecorder, 2)
			for range 2 {
				go func() { responses <- f.request(ctx, f.form(grant)) }()
			}
			first, second := <-responses, <-responses
			if first.Code > second.Code {
				first, second = second, first
			}
			if first.Code != http.StatusOK || second.Code != http.StatusBadRequest {
				t.Fatalf("concurrent redemption statuses=%d,%d", first.Code, second.Code)
			}
			delegationAuditToken(t, first)
			var issued int
			if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'agent.access.issue'`).Scan(&issued); err != nil || issued != 1 {
				t.Fatalf("concurrent redemption issued %d tokens: %v", issued, err)
			}
		})
	}
}

func TestOAuthRefreshReplayAuditFailureRollsBackRevocation(t *testing.T) {
	f := newRedemptionFixture(t)
	ctx := context.Background()
	first := f.request(ctx, f.form("refresh_token"))
	delegationAuditToken(t, first)
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil || body.RefreshToken == "" {
		t.Fatal("refresh response omitted successor")
	}
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_refresh_replay_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'agent.oauth_refresh.replay' THEN RAISE EXCEPTION 'replay audit rejected'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_refresh_replay_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_refresh_replay_audit()`); err != nil {
		t.Fatal(err)
	}
	if response := f.request(ctx, f.form("refresh_token")); response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "access_token") {
		t.Fatalf("replay audit failure status=%d", response.Code)
	}
	var revoked, events int
	if err := f.store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_credentials WHERE revoked_at IS NOT NULL),
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth_refresh.replay')`).Scan(&revoked, &events); err != nil || revoked != 0 || events != 0 {
		t.Fatalf("failed replay audit partially revoked family: revoked=%d events=%d error=%v", revoked, events, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_refresh_replay_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if response := f.request(ctx, f.form("refresh_token")); response.Code != http.StatusBadRequest {
		t.Fatalf("replay retry status=%d", response.Code)
	}
	form := f.form("refresh_token")
	form.Set("refresh_token", body.RefreshToken)
	if response := f.request(ctx, form); response.Code != http.StatusBadRequest {
		t.Fatalf("successor survived committed replay: status=%d", response.Code)
	}
}
