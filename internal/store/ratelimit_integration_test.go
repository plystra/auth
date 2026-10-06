package store_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

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
