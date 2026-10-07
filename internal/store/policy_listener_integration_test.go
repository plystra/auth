package store_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

func TestPolicyListenerInvalidatesOnCommitAndReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = harness.Close(context.Background()) }()
	database, err := harness.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close(context.Background()) }()
	st, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var notified atomic.Bool
	listener := store.NewPolicyListener(ctx, st.Pool, func() { notified.Store(true) })
	defer func() { _ = listener.Close(context.Background()) }()
	waitForInvalidations(t, listener, 1)

	if _, err := st.Pool.Exec(ctx, `SELECT pg_notify('auth_policy', 'spc_test')`); err != nil {
		t.Fatal(err)
	}
	waitForInvalidations(t, listener, 2)

	listener.Disconnect()
	waitForInvalidations(t, listener, 3)
	if !notified.Load() {
		t.Fatal("invalidation callback was not called")
	}
}

func waitForInvalidations(t *testing.T, listener *store.PolicyListener, want uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if listener.InvalidationCount() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("invalidations = %d, want at least %d", listener.InvalidationCount(), want)
}
