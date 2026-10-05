package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var agentDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	agentDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := agentDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestAgentGroupsAreUniqueNestedAndBoundedByExpiry(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	agents := &Service{Store: st}

	defaultAgent, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "default-expiry"})
	if err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(defaultAgent.ExpiresAt); remaining < 29*24*time.Hour || remaining > 30*24*time.Hour+time.Minute {
		t.Fatalf("default expiry = %s, want approximately 30 days", remaining)
	}

	parentExpiry := time.Now().UTC().Add(2 * time.Hour)
	parent, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "parent", ExpiresAt: parentExpiry})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: parent.ID, Name: "child", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: parent.ID, Name: "too-late", ExpiresAt: parentExpiry.Add(time.Minute)}); err == nil {
		t.Fatal("child expiry exceeded its owner expiry")
	} else {
		assertAgentError(t, err, "VALIDATION_FAILED")
	}
	if _, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "too-long", ExpiresAt: time.Now().UTC().Add(91 * 24 * time.Hour)}); err == nil {
		t.Fatal("agent expiry exceeded the 90-day limit")
	} else {
		assertAgentError(t, err, "VALIDATION_FAILED")
	}

	var ownerGroup, parentGroup, childGroup, parentOfChild string
	if err := st.Pool.QueryRow(ctx, `SELECT id FROM groups WHERE owner_member_id = $1 AND kind = 'agents' AND status <> 'removed'`, owner.ID).Scan(&ownerGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT home_group_id FROM members WHERE id = $1`, parent.ID).Scan(&parentGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT home_group_id FROM members WHERE id = $1`, child.ID).Scan(&childGroup); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT parent_id FROM groups WHERE id = $1`, childGroup).Scan(&parentOfChild); err != nil {
		t.Fatal(err)
	}
	if ownerGroup != parentGroup || parentOfChild != parentGroup {
		t.Fatalf("agent groups are not nested under the owner group: owner=%s parent=%s child_parent=%s", ownerGroup, parentGroup, parentOfChild)
	}
	var ownerGroups int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE owner_member_id = $1 AND kind = 'agents' AND status <> 'removed'`, owner.ID).Scan(&ownerGroups); err != nil {
		t.Fatal(err)
	}
	if ownerGroups != 1 {
		t.Fatalf("active owner agent groups = %d, want 1", ownerGroups)
	}
}

func TestAgentStopAndDeleteRevokeCredentialsAcrossSubtreeAndKeepTombstones(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	agents := &Service{Store: st}
	parent, parentKey, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "stop-parent", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(ctx, CreateInput{OwnerMemberID: parent.ID, Name: "stop-child", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agents.Stop(ctx, owner.ID, parent.ID); err != nil {
		t.Fatal(err)
	}
	assertMemberStatus(t, st, parent.ID, "suspended")
	assertMemberStatus(t, st, child.ID, "suspended")
	if _, err := agents.AuthenticateKey(ctx, parentKey); err == nil {
		t.Fatal("stopping an agent left its credential usable")
	}
	if _, err := agents.AuthenticateKey(ctx, childKey); err == nil {
		t.Fatal("stopping an agent left a child credential usable")
	}

	deleteParent, parentKey, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "delete-parent", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	deleteChild, childKey, err := agents.Create(ctx, CreateInput{OwnerMemberID: deleteParent.ID, Name: "delete-child", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := agents.Delete(ctx, owner.ID, deleteParent.ID); err != nil {
		t.Fatal(err)
	}
	assertMemberStatus(t, st, deleteParent.ID, "removed")
	assertMemberStatus(t, st, deleteChild.ID, "removed")
	var parentDeletedAt, childDeletedAt time.Time
	if err := st.Pool.QueryRow(ctx, `SELECT deleted_at FROM members WHERE id = $1`, deleteParent.ID).Scan(&parentDeletedAt); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT deleted_at FROM members WHERE id = $1`, deleteChild.ID).Scan(&childDeletedAt); err != nil {
		t.Fatal(err)
	}
	if parentDeletedAt.IsZero() || childDeletedAt.IsZero() {
		t.Fatal("deleted agent subtree did not retain deletion tombstones")
	}
	if _, err := agents.AuthenticateKey(ctx, parentKey); err == nil {
		t.Fatal("deleting an agent left its credential usable")
	}
	if _, err := agents.AuthenticateKey(ctx, childKey); err == nil {
		t.Fatal("deleting an agent left a child credential usable")
	}
	var removedGroups int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM groups g
		JOIN members m ON m.home_group_id = g.id
		WHERE m.id IN ($1, $2) AND g.status = 'removed'
	`, deleteParent.ID, deleteChild.ID).Scan(&removedGroups); err != nil {
		t.Fatal(err)
	}
	if removedGroups != 2 {
		t.Fatalf("removed agent groups = %d, want 2", removedGroups)
	}
}

func newAgentFixture(t *testing.T) (*store.Store, *authorization.Service, authorization.Member, string) {
	t.Helper()
	ctx := context.Background()
	database, err := agentDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_agent_owner', 'agent-owner@example.test', 'agent-owner@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	space, member, err := authz.CreateSpace(ctx, "usr_agent_owner", "Agent Test Space", "agent-test-space")
	if err != nil {
		t.Fatal(err)
	}
	return st, authz, member, space.ID
}

func assertMemberStatus(t *testing.T, st *store.Store, memberID, want string) {
	t.Helper()
	var got string
	if err := st.Pool.QueryRow(context.Background(), `SELECT status FROM members WHERE id = $1`, memberID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("member %s status = %q, want %q", memberID, got, want)
	}
}

func assertAgentError(t *testing.T, err error, want string) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != want {
		t.Fatalf("error = %v, want API error %q", err, want)
	}
}
