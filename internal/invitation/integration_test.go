package invitation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var invitationDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	invitationDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := invitationDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestInvitationTokensAreHashedSingleUseAndExpire(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	svc := &Service{Store: st}

	inv, raw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "  Invitee@Example.Test ", MemberID: "mem_invitation_target"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.EmailNormalized != "invitee@example.test" {
		t.Fatalf("normalized email = %q", inv.EmailNormalized)
	}
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM invitation_tokens WHERE id = $1`, inv.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if string(stored) == raw || len(stored) != 32 {
		t.Fatal("invitation token was stored in plaintext or with the wrong digest length")
	}

	consumed, err := svc.Consume(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.ID != inv.ID || consumed.ConsumedAt == nil {
		t.Fatalf("consumed invitation = %+v", consumed)
	}
	if _, err := svc.Consume(ctx, raw); !hasCode(err, "invalid_grant") {
		t.Fatalf("second consume error = %v, want invalid_grant", err)
	}

	_, expiredRaw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "expired@example.test", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE invitation_tokens SET expires_at = now() - interval '1 second' WHERE email_normalized = 'expired@example.test'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Consume(ctx, expiredRaw); !hasCode(err, "invalid_grant") {
		t.Fatalf("expired consume error = %v, want invalid_grant", err)
	}
}

func TestInvitationTokenConcurrentConsumptionIsSingleUse(t *testing.T) {
	ctx := context.Background()
	st := newInvitationStore(t)
	svc := &Service{Store: st}
	_, raw, err := svc.Create(ctx, CreateInput{SpaceID: "spc_01h00000000000000000000000", Email: "race@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, consumeErr := svc.Consume(ctx, raw)
			results <- consumeErr
		}()
	}
	wg.Wait()
	close(results)

	var successes, invalid int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case hasCode(err, "invalid_grant"):
			invalid++
		default:
			t.Fatalf("unexpected concurrent consume error: %v", err)
		}
	}
	if successes != 1 || invalid != attempts-1 {
		t.Fatalf("concurrent consume results: successes=%d invalid=%d", successes, invalid)
	}
}

func newInvitationStore(t *testing.T) *store.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := invitationDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	st, err := store.Open(ctx, db.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO members (id, space_id, name, type) VALUES ('mem_invitation_target', 'spc_01h00000000000000000000000', 'Invitation target', 'human')`); err != nil {
		t.Fatal(err)
	}
	return st
}

func hasCode(err error, code string) bool {
	var e *apierr.Error
	return errors.As(err, &e) && e.Code == code
}
