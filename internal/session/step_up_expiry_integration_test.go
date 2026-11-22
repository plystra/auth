package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/store"
)

func TestPrincipalStepUpRechecksProofAndSessionExpiryAfterRowLock(t *testing.T) {
	for _, deadline := range []string{"proof", "session"} {
		t.Run(deadline, func(t *testing.T) {
			ctx := t.Context()
			database, err := sessionDB.Clone(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close(context.Background()) })
			st, err := store.Open(ctx, database.URL)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(st.Close)
			if _, err := st.Pool.Exec(ctx, `INSERT INTO users(id,email,email_normalized,password_hash,status)
				VALUES ('usr_consume_deadline','deadline@example.test','deadline@example.test','unused','active')`); err != nil {
				t.Fatal(err)
			}
			digest := bytes.Repeat([]byte{'d'}, 32)
			var expires time.Time
			if err := st.Pool.QueryRow(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,step_up_method,step_up_operation,step_up_digest,step_up_expires_at)
				VALUES ('ses_consume_deadline','usr_consume_deadline',$1,
				    clock_timestamp()+CASE WHEN $2='session' THEN interval '2 seconds' ELSE interval '1 hour' END,
				    'totp','sso_connections.list',$1,
				    clock_timestamp()+CASE WHEN $2='proof' THEN interval '2 seconds' ELSE interval '5 minutes' END)
				RETURNING least(expires_at,step_up_expires_at)`, digest, deadline).Scan(&expires); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			ctx = WithStepUpRequirement(ctx, StepUpRequirement{SessionID: "ses_consume_deadline", Operation: "sso_connections.list", Digest: digest})
			lock, err := st.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lock.Rollback(context.Background()) }()
			if err := st.InTx(lock.Context(ctx), func(q *db.Queries) error {
				_, err := q.LockSessionForStepUp(ctx, db.LockSessionForStepUpParams{ID: "ses_consume_deadline"})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- st.InTx(ctx, func(q *db.Queries) error { return (&Service{Store: st}).ConsumeStepUpTx(ctx, q) })
			}()
			for {
				var started *time.Time
				if err := st.Pool.QueryRow(ctx, `SELECT min(query_start) FROM pg_stat_activity WHERE datname=current_database()
					AND wait_event_type='Lock' AND (query LIKE '%ConsumeSessionStepUp%' OR query LIKE '%LockSessionForStepUp%')`).Scan(&started); err != nil {
					t.Fatal(err)
				}
				if started != nil {
					if !started.Before(expires) {
						t.Fatal("consumer did not start before expiry")
					}
					break
				}
				select {
				case err := <-done:
					t.Fatalf("step-up consumption did not wait on its session: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			// The blocker only holds the row; it deliberately does not update
			// its version or cause PostgreSQL to re-evaluate an UPDATE predicate.
			if _, err := st.Pool.Exec(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())),0)::double precision)`, expires); err != nil {
				t.Fatal(err)
			}
			if err := lock.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var failure *apierr.Error
			if err := <-done; !errors.As(err, &failure) || failure.Code != "STEP_UP_REQUIRED" {
				t.Fatalf("expired %s accepted or misreported: %v", deadline, err)
			}
			var retained bool
			if err := st.Pool.QueryRow(ctx, "SELECT step_up_digest=$1 AND step_up_operation='sso_connections.list' FROM sessions WHERE id='ses_consume_deadline'", digest).Scan(&retained); err != nil || !retained {
				t.Fatalf("denied consumption altered the session proof: %v", err)
			}
		})
	}
}
