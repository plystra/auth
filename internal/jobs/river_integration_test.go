package jobs_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

type testArgs struct {
	Value string `json:"value"`
}

func (testArgs) Kind() string { return "auth.test" }

var riverDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	riverDB, err = testdb.Start(ctx)
	if err != nil {
		panic(err)
	}
	code := m.Run()
	if err := riverDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestRiverEnqueueSharesBusinessTransactionAndRollsBackWithIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dbInfo, err := riverDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dbInfo.Close(context.Background()) }()

	st, err := store.Open(ctx, dbInfo.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	rollbackErr := st.InTx(ctx, func(q *db.Queries) error {
		if err := st.Jobs.InsertTx(ctx, q, testArgs{Value: "rolled-back"}); err != nil {
			return err
		}
		return errors.New("business mutation failed")
	})
	if rollbackErr == nil {
		t.Fatal("rollback transaction unexpectedly succeeded")
	}
	assertRiverJobCount(t, ctx, st, 0)

	if err := st.InTx(ctx, func(q *db.Queries) error {
		return st.Jobs.InsertTx(ctx, q, testArgs{Value: "committed"})
	}); err != nil {
		t.Fatal(err)
	}
	assertRiverJobCount(t, ctx, st, 1)
}

func assertRiverJobCount(t *testing.T, ctx context.Context, st *store.Store, want int) {
	t.Helper()
	var got int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM river_job`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("river jobs = %d, want %d", got, want)
	}
}
