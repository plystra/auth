package operator

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
)

func TestOperatorRechecksSessionAndProofAfterIdentityLock(t *testing.T) {
	for _, tc := range []struct {
		name, deadline string
		validate       bool
	}{
		{"proof", "proof", false}, {"absolute session", "absolute", false}, {"idle session", "idle", false}, {"access token", "access", false},
		{"idempotency replay validation", "idle", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newOperatorStore(t)
			const user = "usr_operator_deadline"
			const target = "usr_operator_deadline_target"
			insertOperator(t, st, user, "deadline", `["*"]`)
			insertOperator(t, st, target, "deadline-target", `["ops:operators:read"]`)
			key := []byte(strings.Repeat("h", 32))
			digest := sha256.Sum256([]byte("operator-update-test"))
			raw := insertOperatorSession(t, st, user, key, &digest)
			svc, err := New(st, &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}, [][]byte{key})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			gate, err := st.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = gate.Rollback(context.Background()) }()
			if err := st.InTx(gate.Context(ctx), func(q *db.Queries) error {
				_, err := q.LockOperator(ctx, db.LockOperatorParams{UserID: user})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			var expires time.Time
			if err := st.Pool.QueryRow(ctx, `UPDATE operator_sessions SET
				expires_at=CASE WHEN $2='absolute' THEN clock_timestamp()+interval '2 seconds' ELSE expires_at END,
				idle_expires_at=CASE WHEN $2='idle' THEN clock_timestamp()+interval '2 seconds' ELSE idle_expires_at END,
				access_expires_at=CASE WHEN $2='access' THEN clock_timestamp()+interval '2 seconds' ELSE access_expires_at END,
				step_up_expires_at=CASE WHEN $2='proof' THEN clock_timestamp()+interval '2 seconds' ELSE step_up_expires_at END
				WHERE user_id=$1 RETURNING least(expires_at,idle_expires_at,access_expires_at,step_up_expires_at)`, user, tc.deadline).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if tc.validate {
					done <- svc.Validate(ctx, raw)
					return
				}
				done <- svc.UpdateCapabilities(ctx, raw, target, []string{"ops:operators:manage"}, digest[:])
			}()
			for {
				var started *time.Time
				if err := st.Pool.QueryRow(ctx, `SELECT min(query_start) FROM pg_stat_activity WHERE datname=current_database()
					AND wait_event_type='Lock' AND query LIKE '%LockOperatorIdentity%'`).Scan(&started); err != nil {
					t.Fatal(err)
				}
				if started != nil {
					if !started.Before(expires) {
						t.Fatal("operation started after expiry")
					}
					break
				}
				select {
				case err := <-done:
					t.Fatalf("request did not wait for its operator identity: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if _, err := st.Pool.Exec(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())),0)::double precision)`, expires); err != nil {
				t.Fatal(err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			want := "UNAUTHENTICATED"
			if tc.deadline == "proof" {
				want = "STEP_UP_REQUIRED"
			}
			assertOperatorError(t, <-done, want)
			var unchanged bool
			if err := st.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM operators WHERE user_id=$2 AND capabilities='["ops:operators:read"]')
				AND EXISTS(SELECT 1 FROM operator_sessions WHERE user_id=$1 AND step_up_digest=$3)
				AND NOT EXISTS(SELECT 1 FROM audit_logs WHERE action='ops.operators.update' AND outcome='success')`, user, target, digest[:]).Scan(&unchanged); err != nil || !unchanged {
				t.Fatalf("expired operation changed authority, consumed a proof, or recorded success: %v", err)
			}
		})
	}
}
