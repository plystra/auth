package authorization

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

func TestBindUserRejectsNonHumanMember(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	applicationID := "mem_application_binding_test"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status)
		VALUES ($1, $2, 'Application member', 'service', 'application', 'single', 'active')
	`, applicationID, spaceID); err != nil {
		t.Fatalf("insert application member: %v", err)
	}
	if err := svc.BindUser(ctx, actor.ID, spaceID, applicationID, "usr_binding_target"); err == nil {
		t.Fatal("BindUser accepted an application member")
	} else {
		assertAPIErrorCode(t, err, "VALIDATION_FAILED")
	}
}

func TestSingleBindingSerializesConcurrentBinds(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	target, err := svc.CreateMember(ctx, actor.ID, "", spaceID, "Shared human", "human", "single")
	if err != nil {
		t.Fatalf("create target member: %v", err)
	}
	if err := insertUser(ctx, st, "usr_binding_target", "binding-target@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := insertUser(ctx, st, "usr_binding_other", "binding-other@example.test"); err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, userID := range []string{"usr_binding_target", "usr_binding_other"} {
		userID := userID
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.BindUser(ctx, actor.ID, spaceID, target.ID, userID)
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	conflicts := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "CONFLICT" {
			t.Fatalf("unexpected concurrent bind error: %v", err)
		}
		conflicts++
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent single binding results: successes=%d conflicts=%d", successes, conflicts)
	}

	var count int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM user_members
		WHERE member_id = $1 AND status = 'active' AND revoked_at IS NULL
	`, target.ID).Scan(&count); err != nil {
		t.Fatalf("count active bindings: %v", err)
	}
	if count != 1 {
		t.Fatalf("active binding count = %d, want 1", count)
	}
}

func newBindingFixture(t *testing.T) (*store.Store, *Service, Member, string) {
	t.Helper()
	ctx := context.Background()
	database, err := integrationDB.Clone(ctx)
	if err != nil {
		t.Fatalf("clone test database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(context.Background()); err != nil {
			t.Errorf("drop test database: %v", err)
		}
	})
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(st.Close)
	if err := insertUser(ctx, st, "usr_binding_actor", "binding-actor@example.test"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st}
	space, actor, err := svc.CreateSpace(ctx, "usr_binding_actor", "Binding Test Space", "binding-test-space")
	if err != nil {
		t.Fatalf("create binding test space: %v", err)
	}
	return st, svc, actor, space.ID
}

func insertUser(ctx context.Context, st *store.Store, id, email string) error {
	_, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ($1, $2, $2, 'test-password-hash', 'active')
	`, id, email)
	return err
}

func assertAPIErrorCode(t *testing.T, err error, want string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) {
		t.Fatalf("error = %v, want API error %s", err, want)
	}
	if public.Code != want {
		t.Fatalf("error code = %q, want %q", public.Code, want)
	}
}
