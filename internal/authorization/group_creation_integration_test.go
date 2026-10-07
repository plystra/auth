package authorization

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
)

func TestCreateStandardGroupEnforcesSingleRoot(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)

	root, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Operations", "")
	if err != nil {
		t.Fatalf("create standard root: %v", err)
	}
	if root.Kind != "standard" || root.Status != "active" || root.ParentID != "" || root.SpaceID != spaceID {
		t.Fatalf("created root = %+v, want active standard root in Space", root)
	}

	if _, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Finance", ""); err == nil {
		t.Fatal("second standard root was accepted")
	} else {
		assertAPIErrorCode(t, err, "CONFLICT")
	}
	var roots int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM groups
		WHERE space_id = $1 AND kind = 'standard' AND parent_id IS NULL AND status <> 'removed'
	`, spaceID).Scan(&roots); err != nil {
		t.Fatal(err)
	}
	if roots != 1 {
		t.Fatalf("active standard roots = %d, want 1", roots)
	}
}

func TestCreateStandardGroupValidatesParentFacts(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	root, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Operations", "")
	if err != nil {
		t.Fatal(err)
	}

	otherSpace, otherActor, err := svc.CreateSpace(ctx, "usr_binding_actor", "Other Group Space", "other-group-space")
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := svc.CreateGroup(ctx, otherActor.ID, otherSpace.ID, "Other root", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Cross-space child", otherRoot.ID); err == nil {
		t.Fatal("cross-Space parent was accepted")
	} else {
		assertAPIErrorCode(t, err, "NOT_FOUND")
	}

	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: actor.ID, Name: "group-owner", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Agent child", created.HomeGroupID); err == nil {
		t.Fatal("manual child under Agent group was accepted")
	} else {
		assertAPIErrorCode(t, err, "PERMISSION_DENIED")
	}

	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET status = 'suspended' WHERE id = $1`, root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Inactive child", root.ID); err == nil {
		t.Fatal("child under inactive group was accepted")
	} else {
		assertAPIErrorCode(t, err, "GROUP_INACTIVE")
	}
}

func TestCreateStandardGroupEnforcesMaximumDepth(t *testing.T) {
	ctx := context.Background()
	_, svc, actor, spaceID := newBindingFixture(t)
	parent, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Level 1", "")
	if err != nil {
		t.Fatal(err)
	}
	for level := 2; level <= maxGroupDepth; level++ {
		parent, err = svc.CreateGroup(ctx, actor.ID, spaceID, "Level "+strconv.Itoa(level), parent.ID)
		if err != nil {
			t.Fatalf("create level %d: %v", level, err)
		}
	}
	if _, err := svc.CreateGroup(ctx, actor.ID, spaceID, "Too deep", parent.ID); err == nil {
		t.Fatal("group beyond maximum depth was accepted")
	} else {
		assertAPIErrorCode(t, err, "VALIDATION_FAILED")
	}
}

func TestConcurrentStandardRootCreationAllowsOnlyOne(t *testing.T) {
	ctx := context.Background()
	_, svc, actor, spaceID := newBindingFixture(t)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"Concurrent A", "Concurrent B"} {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.CreateGroup(ctx, actor.ID, spaceID, name, "")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	var successes, conflicts int
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "CONFLICT" {
			t.Fatalf("concurrent root error = %v, want CONFLICT", err)
		}
		conflicts++
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent root results = successes %d conflicts %d, want one each", successes, conflicts)
	}
}
