package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
)

func TestNodeMutationRetainsHumanIdentityLocksUntilCommit(t *testing.T) {
	for _, change := range []string{"account", "binding"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			st, svc, actor, spaceID := newBindingFixture(t)
			mutation, err := st.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
			actorContext := WithHumanActor(mutation.Context(ctx), actor.ID, "usr_binding_actor")
			if err := st.InTx(actorContext, func(q *db.Queries) error {
				decision, err := svc.CheckNodeTx(actorContext, q, CheckRequest{
					MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID,
				})
				if err != nil {
					return err
				}
				if decision.Effect != engine.Allow {
					t.Fatalf("active human denied: %s", decision.Code)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			writer := make(chan error, 1)
			go func() {
				if change == "binding" {
					writer <- svc.RevokeOwnBinding(ctx, "usr_binding_actor", actor.ID)
					return
				}
				writer <- st.InTx(ctx, func(q *db.Queries) error {
					return q.SetUserStatus(ctx, db.SetUserStatusParams{ID: "usr_binding_actor", Status: "disabled"})
				})
			}()
			for {
				var waiting bool
				if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
					WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-writer:
					t.Fatalf("identity revocation bypassed the authorization locks: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if err := mutation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			if err := st.InTx(ctx, func(q *db.Queries) error {
				_, err := svc.CheckNodeTx(WithHumanActor(ctx, actor.ID, "usr_binding_actor"), q, CheckRequest{
					MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID,
				})
				return err
			}); err == nil {
				t.Fatal("the next mutation retained revoked human authority")
			} else {
				assertAPIErrorCode(t, err, "UNAUTHENTICATED")
			}
		})
	}
}

func TestNodeMutationRejectsInvalidHumanIdentity(t *testing.T) {
	for _, condition := range []string{"other_member", "missing_user", "missing_binding", "expired_binding", "revoked_binding", "inactive_user"} {
		t.Run(condition, func(t *testing.T) {
			ctx := context.Background()
			st, svc, actor, spaceID := newBindingFixture(t)
			memberID, userID := actor.ID, "usr_binding_actor"
			var err error
			switch condition {
			case "other_member":
				memberID = "mem_different_actor"
			case "missing_user":
				userID = "usr_nonexistent_actor"
			case "missing_binding":
				if err := insertUser(ctx, st, "usr_unbound_actor", "unbound-actor@example.test"); err != nil {
					t.Fatal(err)
				}
				userID = "usr_unbound_actor"
			case "expired_binding":
				_, err = st.Pool.Exec(ctx, `UPDATE user_members SET expires_at = now() - interval '1 second' WHERE member_id = $1`, actor.ID)
			case "revoked_binding":
				_, err = st.Pool.Exec(ctx, `UPDATE user_members SET status = 'revoked', revoked_at = now() WHERE member_id = $1`, actor.ID)
			case "inactive_user":
				_, err = st.Pool.Exec(ctx, `UPDATE users SET status = 'suspended' WHERE id = $1`, userID)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = st.InTx(ctx, func(q *db.Queries) error {
				_, err := svc.CheckNodeTx(WithHumanActor(ctx, memberID, userID), q, CheckRequest{
					MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID,
				})
				return err
			})
			assertAPIErrorCode(t, err, "UNAUTHENTICATED")
		})
	}
}
