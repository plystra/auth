package protocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/security"
)

func revokeAccessRequest(ctx context.Context, handler http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{"token": {token}}.Encode())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	return out
}

func TestOAuthAccessRevocationRejectsUnverifiedOrInactiveIdentity(t *testing.T) {
	for _, scenario := range []string{"Malformed", "ForgedSignature", "WrongIssuer", "WrongAudience", "WrongType", "Expired", "UnknownSubject", "ForgedSubject", "OldEpoch"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx := context.Background()
			claims, err := f.sessions.Signer.Verify(f.parentToken, time.Now(), "app_redemption")
			if err != nil {
				t.Fatal(err)
			}
			var token string
			switch scenario {
			case "Malformed":
				token = "not.a.jwt"
			case "ForgedSignature":
				parts := strings.Split(f.parentToken, ".")
				parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
				token = strings.Join(parts, ".")
			case "WrongIssuer":
				claims.Issuer = "https://attacker.test"
			case "WrongAudience":
				claims.Audience = "app_other"
			case "WrongType":
				claims.Type = "user"
			case "Expired":
				claims.ExpiresAt = time.Now().Add(-time.Second).Unix()
			case "UnknownSubject":
				claims.Subject, claims.MemberID = "mem_missing", "mem_missing"
			case "ForgedSubject":
				childToken, err := f.sessions.CreateAgentAccess(ctx, f.child.ID, f.owner.SpaceID, "app_redemption")
				if err != nil {
					t.Fatal(err)
				}
				parts := strings.Split(childToken.AccessToken, ".")
				payload, err := json.Marshal(claims)
				if err != nil {
					t.Fatal(err)
				}
				parts[1] = base64.RawURLEncoding.EncodeToString(payload)
				token = strings.Join(parts, ".")
			case "OldEpoch":
				if err := f.store.InTx(ctx, func(q *db.Queries) error {
					if err := member.LockChainsTx(ctx, q, f.agent.ID); err != nil {
						return err
					}
					if err := q.StopAgentMember(ctx, db.StopAgentMemberParams{MemberID: f.agent.ID}); err != nil {
						return err
					}
					return q.ResumeSuspendedAgent(ctx, db.ResumeSuspendedAgentParams{MemberID: f.agent.ID})
				}); err != nil {
					t.Fatal(err)
				}
				token = f.parentToken
			}
			if token == "" {
				token, err = f.sessions.Signer.Sign(claims)
				if err != nil {
					t.Fatal(err)
				}
			}
			out := revokeAccessRequest(ctx, f.handler, token)
			if out.Code != http.StatusOK || out.Body.Len() != 0 {
				t.Fatalf("invalid access revocation disclosed credential state: status=%d", out.Code)
			}
			var inactive, events int
			if err := f.store.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM members WHERE id IN ($1, $2) AND status <> 'active'),
				(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth.revoke')`, f.agent.ID, f.child.ID).Scan(&inactive, &events); err != nil || inactive != 0 || events != 0 {
				t.Fatal("unverified or inactive token revoked a current Agent identity")
			}
		})
	}
}

func TestOAuthAccessRevocationRollsBackAuditAndCommitFailures(t *testing.T) {
	for _, failure := range []string{"Audit", "Commit"} {
		t.Run(failure, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx := context.Background()
			childToken := delegationAuditToken(t, f.exchange(ctx, "app_redemption", "auth.members:read"))
			if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_access_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW.action = 'agent.oauth.revoke' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`); err != nil {
				t.Fatal(err)
			}
			trigger := `CREATE TRIGGER reject_access_revoke BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_access_revoke()`
			if failure == "Commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_access_revoke AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_access_revoke()`
			}
			if _, err := f.store.Pool.Exec(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			out := revokeAccessRequest(ctx, f.handler, f.parentToken)
			if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "temporarily_unavailable") {
				t.Fatalf("failed %s was reported as successful revocation: status=%d", failure, out.Code)
			}
			for _, token := range []string{f.parentToken, childToken} {
				if _, active, err := f.sessions.Introspect(ctx, token, "app_redemption"); err != nil || !active {
					t.Fatal("failed revocation left identity state partially changed")
				}
			}
			var revoked, events int
			if err := f.store.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM agent_credentials WHERE revoked_at IS NOT NULL),
				(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth.revoke')`).Scan(&revoked, &events); err != nil || revoked != 0 || events != 0 {
				t.Fatal("failed revocation retained credential changes or success audit")
			}
			if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_access_revoke ON audit_logs`); err != nil {
				t.Fatal(err)
			}
			if out := revokeAccessRequest(ctx, f.handler, f.parentToken); out.Code != http.StatusOK {
				t.Fatal("revocation could not be retried after rollback")
			}
			if out := revokeAccessRequest(ctx, f.handler, f.parentToken); out.Code != http.StatusOK {
				t.Fatal("repeated revocation was not idempotent")
			}
			if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth.revoke'`).Scan(&events); err != nil || events != 1 {
				t.Fatal("repeated revocation duplicated the committed success event")
			}
		})
	}
}

func TestOAuthAccessRevocationRechecksEpochAfterLifecycleWait(t *testing.T) {
	f := newOAuthDelegationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mutation, err := f.store.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
	if err := f.store.InTx(mutation.Context(ctx), func(q *db.Queries) error { return member.LockChainsTx(ctx, q, f.agent.ID) }); err != nil {
		t.Fatal(err)
	}
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- revokeAccessRequest(ctx, f.handler, f.parentToken) }()
	waitForRedemptionLock(t, ctx, f.store, response)
	if err := f.store.InTx(mutation.Context(ctx), func(q *db.Queries) error {
		if err := q.StopAgentMember(ctx, db.StopAgentMemberParams{MemberID: f.agent.ID}); err != nil {
			return err
		}
		return q.ResumeSuspendedAgent(ctx, db.ResumeSuspendedAgentParams{MemberID: f.agent.ID})
	}); err != nil {
		t.Fatal(err)
	}
	if err := mutation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if out := <-response; out.Code != http.StatusOK {
		t.Fatal("inactive access revocation disclosed lifecycle state")
	}
	current, err := f.sessions.CreateAgentAccess(ctx, f.agent.ID, f.owner.SpaceID, "app_redemption")
	if err != nil {
		t.Fatal(err)
	}
	if _, active, err := f.sessions.Introspect(ctx, current.AccessToken, "app_redemption"); err != nil || !active {
		t.Fatal("old access token revoked the resumed Agent identity")
	}
}

func TestOAuthGovernanceAccessTokenCanRevokeItsOAuthRoot(t *testing.T) {
	f := newGovernanceFixture(t)
	ctx := context.Background()
	token := delegationAuditToken(t, f.request(ctx, governanceForm(f)))
	if out := revokeAccessRequest(ctx, f.handler, token); out.Code != http.StatusOK {
		t.Fatal("valid governance token could not revoke its OAuth root")
	}
	if _, active, err := f.sessions.Introspect(ctx, token, security.DefaultApplicationAudience); err != nil || active {
		t.Fatal("revoked governance token retained an active Agent identity")
	}
}
