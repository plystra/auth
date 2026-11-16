package authorization

import (
	"context"
	"slices"
	"testing"

	"github.com/plystra/auth/internal/authz/engine"
)

func TestAuthorizationTraceIncludesOnlyResolvedFactsAndIsStableOnCacheHits(t *testing.T) {
	ctx := context.Background()
	st, svc, actor, spaceID := newBindingFixture(t)
	in := CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: spaceID}
	first, _, err := svc.Check(ctx, in)
	if err != nil || first.Effect != engine.Allow {
		t.Fatalf("initial decision = %+v, %v", first, err)
	}
	for range 3 {
		cached, _, err := svc.Check(ctx, in)
		if err != nil || !slices.Equal(first.Trace, cached.Trace) {
			t.Fatal("a repeated decision duplicated or changed evaluated stages")
		}
		cached.Trace[0].Detail = "caller mutation"
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, actor.ID); err != nil {
		t.Fatal(err)
	}
	inactive, _, err := svc.Check(ctx, in)
	if err != nil || inactive.Code != "ACTOR_MEMBER_INACTIVE" || len(inactive.Trace) != 2 || inactive.Trace[0].Step != "catalog" || inactive.Trace[1] != engine.Reject("ACTOR_MEMBER_INACTIVE").Trace[0] {
		t.Fatalf("inactive subject included unresolved facts: %+v, %v", inactive, err)
	}
	in.Permission = "missing:read"
	missing, _, err := svc.Check(ctx, in)
	if err != nil || missing.Code != "UNKNOWN_PERMISSION" || len(missing.Trace) != 1 {
		t.Fatalf("catalog failure included unevaluated subject facts: %+v, %v", missing, err)
	}
}
