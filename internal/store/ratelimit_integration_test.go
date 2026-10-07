package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/idempotency"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var rateLimitDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	rateLimitDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := rateLimitDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestRateLimitBucketIsSharedAcrossStoresAndDoesNotLoseConcurrentCounts(t *testing.T) {
	ctx := context.Background()
	database, err := rateLimitDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	first, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	second, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Close)
	limiters := [2]store.RateLimiter{{Store: first}, {Store: second}}
	const attempts = 40
	const limit = 12
	start := make(chan struct{})
	results := make(chan bool, attempts)
	errors := make(chan error, attempts)
	var group sync.WaitGroup
	for i := 0; i < attempts; i++ {
		group.Add(1)
		go func(limiter store.RateLimiter) {
			defer group.Done()
			<-start
			allowed, err := limiter.Allow(ctx, "shared-login-limit", limit, time.Hour)
			if err != nil {
				errors <- err
				return
			}
			results <- allowed
		}(limiters[i%len(limiters)])
	}
	close(start)
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	allowed := 0
	for result := range results {
		if result {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("allowed %d of %d attempts across stores, want %d", allowed, attempts, limit)
	}
	var persisted int
	if err := first.Pool.QueryRow(ctx, `SELECT count FROM rate_limit_buckets WHERE bucket_key = 'shared-login-limit'`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != attempts {
		t.Fatalf("persisted count = %d, want %d", persisted, attempts)
	}
}

func TestIdempotencyTransactionCommitsBusinessAndResponseTogether(t *testing.T) {
	ctx := context.Background()
	database, err := rateLimitDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	limiter := &store.RateLimiter{Store: st}

	tx, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txCtx := tx.Context(ctx)
	reserved, err := tx.Reserve(txCtx, idempotency.Request{ScopeHash: "scope", Method: "POST", Path: "/test", Key: "commit", RequestHash: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Allow(txCtx, "idempotent-business", 1, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := tx.Complete(txCtx, reserved.ID, idempotency.Response{StatusCode: 201, Headers: map[string][]string{"Content-Type": {"application/json"}}, Body: []byte(`{"ok":true}`)}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	replayTx, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := replayTx.Reserve(ctx, idempotency.Request{ScopeHash: "scope", Method: "POST", Path: "/test", Key: "commit", RequestHash: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	_ = replayTx.Rollback(ctx)
	if !replay.Replay || replay.StatusCode != 201 || string(replay.Body) != `{"ok":true}` {
		t.Fatalf("replay = %+v, want committed response", replay)
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count FROM rate_limit_buckets WHERE bucket_key = 'idempotent-business'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("business transaction count = %d, want 1", count)
	}

	rollbackTx, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rollbackCtx := rollbackTx.Context(ctx)
	reserved, err = rollbackTx.Reserve(rollbackCtx, idempotency.Request{ScopeHash: "scope", Method: "POST", Path: "/test", Key: "rollback", RequestHash: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Allow(rollbackCtx, "rolled-back-business", 1, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := rollbackTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	checkTx, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check, err := checkTx.Reserve(ctx, idempotency.Request{ScopeHash: "scope", Method: "POST", Path: "/test", Key: "rollback", RequestHash: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	_ = checkTx.Rollback(ctx)
	if check.Replay || check.ID == "" {
		t.Fatalf("rolled-back reservation = %+v, want a new reservation", check)
	}
	var rolledBack int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM rate_limit_buckets WHERE bucket_key = 'rolled-back-business'`).Scan(&rolledBack); err != nil {
		t.Fatal(err)
	}
	if rolledBack != 0 {
		t.Fatalf("rolled-back business rows = %d, want 0", rolledBack)
	}
}

func TestIdempotencyRequestSavepointRollsBackFailedBusinessCallback(t *testing.T) {
	ctx := context.Background()
	database, err := rateLimitDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	limiter := &store.RateLimiter{Store: st}
	tx, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txCtx := tx.Context(ctx)
	reserved, err := tx.Reserve(txCtx, idempotency.Request{ScopeHash: "scope", Method: "POST", Path: "/test", Key: "failed", RequestHash: []byte("body")})
	if err != nil {
		t.Fatal(err)
	}
	// A nested business transaction is rolled back to its savepoint when the
	// enclosing operation reports an error.
	if err := st.InTx(txCtx, func(_ *db.Queries) error {
		if _, err := limiter.Allow(txCtx, "failed-business", 1, time.Hour); err != nil {
			return err
		}
		return errors.New("business failure")
	}); err == nil {
		t.Fatal("failed business callback unexpectedly succeeded")
	}
	if err := tx.Complete(txCtx, reserved.ID, idempotency.Response{StatusCode: 422, Body: []byte(`{"error":"business failure"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM rate_limit_buckets WHERE bucket_key = 'failed-business'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed business rows = %d, want 0", count)
	}
}

func TestConcurrentIdempotencyReservationsHaveOneBusinessOwner(t *testing.T) {
	ctx := context.Background()
	database, err := rateLimitDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	request := idempotency.Request{ScopeHash: "scope", Method: "POST", Path: "/test", Key: "concurrent", RequestHash: []byte("body")}
	first, err := st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstReservation, err := first.Reserve(first.Context(ctx), request)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan idempotency.Reservation, 1)
	errors := make(chan error, 1)
	go func() {
		second, err := st.BeginIdempotency(ctx)
		if err != nil {
			errors <- err
			return
		}
		reserved, err := second.Reserve(ctx, request)
		_ = second.Rollback(ctx)
		if err != nil {
			errors <- err
			return
		}
		result <- reserved
	}()
	if err := first.Complete(first.Context(ctx), firstReservation.ID, idempotency.Response{StatusCode: 201, Body: []byte(`{"ok":true}`)}); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errors:
		t.Fatal(err)
	case replay := <-result:
		if !replay.Replay || replay.StatusCode != 201 {
			t.Fatalf("concurrent reservation = %+v, want replay", replay)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent reservation did not resolve after first commit")
	}
}
