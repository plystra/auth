package idempotency

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var integrationDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	integrationDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := integrationDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestReservationReplaysCompletedResponseAndRejectsChangedRequest(t *testing.T) {
	ctx := context.Background()
	database, err := integrationDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	service := &Service{Store: st}
	first, err := service.Reserve(ctx, "scope", "POST", "/v1/test", "key", []byte("request-one"))
	if err != nil || first.ID == "" {
		t.Fatalf("first reservation = %+v, err=%v", first, err)
	}
	if err := service.Complete(ctx, first.ID, 201, map[string][]string{"Content-Type": {"application/json"}}, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	replay, err := service.Reserve(ctx, "scope", "POST", "/v1/test", "key", []byte("request-one"))
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || replay.StatusCode != 201 || string(replay.Body) != `{"ok":true}` {
		t.Fatalf("replay = %+v, want stored response", replay)
	}
	conflict, err := service.Reserve(ctx, "scope", "POST", "/v1/test", "key", []byte("request-two"))
	if err != nil {
		t.Fatal(err)
	}
	if !conflict.Conflict {
		t.Fatalf("changed request reservation = %+v, want conflict", conflict)
	}
}
