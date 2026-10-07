package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/store"
)

func TestAuthorizationCacheInvalidatesAcrossStoresAfterCommittedRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	database, err := integrationDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close(context.Background()) }()
	first, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := insertUser(ctx, first, "usr_cache_actor", "cache-actor@example.test"); err != nil {
		t.Fatal(err)
	}
	firstService := &Service{Store: first}
	secondService := &Service{Store: second}
	space, actor, err := firstService.CreateSpace(ctx, "usr_cache_actor", "Cache Space", "cache-space")
	if err != nil {
		t.Fatal(err)
	}
	decision, _, err := firstService.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: space.ID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("initial decision = %+v, want allow", decision)
	}
	if firstService.cache == nil || firstService.cacheSize() == 0 {
		t.Fatal("initial authorization decision was not cached")
	}

	var grantID string
	if err := first.Pool.QueryRow(ctx, `
		SELECT id FROM authorization_grants
		WHERE grantee_member_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC, id DESC LIMIT 1
	`, actor.ID).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	baselineInvalidations := first.PolicyListener.InvalidationCount()
	if err := secondService.RevokeGrant(ctx, actor.ID, space.ID, grantID); err != nil {
		t.Fatalf("revocation through second store = %v", err)
	}
	waitForStoreInvalidation(t, first, baselineInvalidations+1)
	if got := firstService.cacheSize(); got != 0 {
		t.Fatalf("first store cache size after notification = %d, want 0", got)
	}
	decision, _, err = firstService.Check(ctx, CheckRequest{MemberID: actor.ID, Permission: "auth.members:manage", ResourceSpace: space.ID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny {
		t.Fatalf("decision after cross-store revocation = %+v, want deny", decision)
	}
}

func TestAuthorizationCacheKeyIncludesAgentVersionChain(t *testing.T) {
	ctx := context.Background()
	st, svc, owner, spaceID := newBindingFixture(t)
	agentService := &agent.Service{Store: st}
	created, _, err := agentService.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "cache-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_cache_agent', $1, '["auth.members:manage"]'::jsonb, $2, 'space', $1, $3)
	`, spaceID, created.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err := svc.Check(ctx, CheckRequest{MemberID: created.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Allow {
		t.Fatalf("initial Agent decision = %+v, want allow", decision)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended', version = version + 1 WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}
	decision, _, err = svc.Check(ctx, CheckRequest{MemberID: created.ID, Permission: "auth.members:manage", ResourceSpace: spaceID})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Effect != engine.Deny || decision.Code != "ACTOR_MEMBER_INACTIVE" {
		t.Fatalf("decision after Agent version change = %+v, want ACTOR_MEMBER_INACTIVE", decision)
	}
}

func (s *Service) cacheSize() int {
	s.cache.mu.RLock()
	defer s.cache.mu.RUnlock()
	return len(s.cache.entries)
}

func waitForStoreInvalidation(t *testing.T, st *store.Store, want uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st.PolicyListener.InvalidationCount() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("policy invalidations = %d, want at least %d", st.PolicyListener.InvalidationCount(), want)
}
