package protocol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/session"
)

func TestAgentExchangeRechecksCredentialsAfterConcurrentRevocation(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		delegated bool
		change    string
	}{
		{"DirectKeyRevoked", false, "key"},
		{"DirectKeyExpired", false, "expiry"},
		{"ChildKeyRevoked", true, "key"},
		{"ChildKeyExpired", true, "expiry"},
		{"ParentStoppedAndResumed", true, "epoch"},
		{"ParentGrantRevoked", true, "grant"},
		{"PermissionDisabled", true, "catalog"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newDelegationAuditFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			locked, release := make(chan struct{}), make(chan struct{})
			writer := make(chan error, 1)
			target := f.parent.ID
			if scenario.delegated {
				target = f.child.ID
			}
			var usedBefore *time.Time
			if err := f.store.Pool.QueryRow(ctx, `SELECT last_used_at FROM agent_credentials WHERE member_id = $1`, target).Scan(&usedBefore); err != nil {
				t.Fatal(err)
			}
			go func() {
				writer <- f.store.InTx(ctx, func(q *db.Queries) error {
					if err := member.LockChainsTx(ctx, q, target); err != nil {
						return err
					}
					close(locked)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					tx, _ := q.Transaction()
					switch scenario.change {
					case "key":
						return q.RevokeAgentCredentials(ctx, db.RevokeAgentCredentialsParams{MemberID: target})
					case "expiry":
						_, err := tx.Exec(ctx, `UPDATE agent_credentials SET expires_at = clock_timestamp() WHERE member_id = $1`, target)
						return err
					case "epoch":
						// Keep the child's current credential valid to isolate the
						// revoked parent JWT from subtree credential revocation.
						if err := q.StopAgentMember(ctx, db.StopAgentMemberParams{MemberID: f.parent.ID}); err != nil {
							return err
						}
						return q.ResumeSuspendedAgent(ctx, db.ResumeSuspendedAgentParams{MemberID: f.parent.ID})
					case "grant":
						_, err := tx.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = $1`, "grt_"+f.parent.ID)
						return err
					default:
						_, err := tx.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:read'`)
						return err
					}
				})
			}()
			select {
			case <-locked:
			case err := <-writer:
				t.Fatalf("could not establish revocation barrier: %v", err)
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() { response <- f.request(ctx, scenario.delegated) }()
			waitForRedemptionLock(t, ctx, f.store, response)
			close(release)
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			out := <-response
			code := "invalid_grant"
			if scenario.change == "grant" || scenario.change == "catalog" {
				code = "invalid_scope"
			}
			if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), code) || strings.Contains(out.Body.String(), "access_token") {
				t.Fatalf("exchange ignored committed %s: status=%d", scenario.change, out.Code)
			}
			var usedAfter *time.Time
			if err := f.store.Pool.QueryRow(ctx, `SELECT last_used_at FROM agent_credentials WHERE member_id = $1`, target).Scan(&usedAfter); err != nil {
				t.Fatal(err)
			}
			if (usedBefore == nil) != (usedAfter == nil) || usedBefore != nil && !usedBefore.Equal(*usedAfter) {
				t.Fatal("rejected exchange committed credential usage")
			}
			var issued int
			if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('agent.access.issue', 'agent.token.exchange')`).Scan(&issued); err != nil || issued != 1 {
				t.Fatalf("rejected exchange wrote a success event: issued=%d error=%v", issued, err)
			}
			if scenario.change == "epoch" {
				f.parentToken = delegationAuditToken(t, f.request(ctx, false))
				delegationAuditToken(t, f.request(ctx, true))
			}
		})
	}
}

func TestAgentExchangeRechecksRotatedKeysBeforeIssuance(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		name := "Direct"
		if delegated {
			name = "Delegated"
		}
		t.Run(name, func(t *testing.T) {
			f := newDelegationAuditFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			mutation, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
			owner, target := f.owner.ID, f.parent.ID
			if delegated {
				owner, target = f.parent.ID, f.child.ID
			}
			next, err := f.agents.Rotate(mutation.Context(ctx), owner, target)
			if err != nil {
				t.Fatal(err)
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() { response <- f.request(ctx, delegated) }()
			waitForRedemptionLock(t, ctx, f.store, response)
			if err := mutation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			out := <-response
			if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_grant") || strings.Contains(out.Body.String(), "access_token") {
				t.Fatalf("exchange accepted a rotated key: status=%d", out.Code)
			}
			if delegated {
				f.childKey = next
			} else {
				f.parentKey = next
			}
			delegationAuditToken(t, f.request(ctx, delegated))
		})
	}
}

func TestAgentExchangeFailureRollsBackCredentialUsage(t *testing.T) {
	for _, delegated := range []bool{false, true} {
		grant := "Direct"
		if delegated {
			grant = "Delegated"
		}
		for _, failure := range []string{"Settings", "Audit", "Commit"} {
			t.Run(grant+"/"+failure, func(t *testing.T) {
				f := newDelegationAuditFixture(t)
				ctx := context.Background()
				target := f.parent.ID
				if delegated {
					target = f.child.ID
				}
				var before, after *time.Time
				if err := f.store.Pool.QueryRow(ctx, `SELECT last_used_at FROM agent_credentials WHERE member_id = $1`, target).Scan(&before); err != nil {
					t.Fatal(err)
				}
				var restore func()
				if failure == "Settings" {
					settings := f.sessions.Settings
					f.sessions.Settings = func(context.Context) (session.Settings, error) {
						return session.Settings{}, errors.New("session settings unavailable")
					}
					restore = func() { f.sessions.Settings = settings }
				} else {
					if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_agent_exchange() RETURNS trigger LANGUAGE plpgsql AS $$
						BEGIN IF NEW.action IN ('agent.access.issue', 'agent.token.exchange') THEN RAISE EXCEPTION 'exchange audit rejected'; END IF; RETURN NEW; END; $$`); err != nil {
						t.Fatal(err)
					}
					trigger := `CREATE TRIGGER reject_agent_exchange BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_agent_exchange()`
					if failure == "Commit" {
						trigger = `CREATE CONSTRAINT TRIGGER reject_agent_exchange AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_agent_exchange()`
					}
					if _, err := f.store.Pool.Exec(ctx, trigger); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_agent_exchange ON audit_logs`); err != nil {
							t.Fatal(err)
						}
					}
				}
				if out := f.request(ctx, delegated); out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "temporarily_unavailable") || strings.Contains(out.Body.String(), "access_token") {
					t.Fatalf("failed exchange status=%d", out.Code)
				}
				if err := f.store.Pool.QueryRow(ctx, `SELECT last_used_at FROM agent_credentials WHERE member_id = $1`, target).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if (before == nil) != (after == nil) || before != nil && !before.Equal(*after) {
					t.Fatal("failed exchange committed credential usage")
				}
				var issued int
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('agent.access.issue', 'agent.token.exchange')`).Scan(&issued); err != nil || issued != 1 {
					t.Fatalf("failed exchange committed a success event: issued=%d error=%v", issued, err)
				}
				restore()
				delegationAuditToken(t, f.request(ctx, delegated))
				if err := f.store.Pool.QueryRow(ctx, `SELECT last_used_at FROM agent_credentials WHERE member_id = $1`, target).Scan(&after); err != nil || after == nil || before != nil && !after.After(*before) {
					t.Fatalf("successful retry did not commit credential usage: error=%v", err)
				}
				if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('agent.access.issue', 'agent.token.exchange')`).Scan(&issued); err != nil || issued != 2 {
					t.Fatalf("successful retry did not commit exactly one event: issued=%d error=%v", issued, err)
				}
			})
		}
	}
}
