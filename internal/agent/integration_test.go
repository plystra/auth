package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
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

func TestAgentCredentialsUseHMACHashesAndRotateKeys(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	oldKey := []byte("agent-credential-hmac-key-00000001")
	newKey := []byte("agent-credential-hmac-key-00000002")
	agents := &Service{Store: st, HMACKeys: [][]byte{oldKey}}
	ag, raw, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "hmac-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.SplitN(raw, ".", 2)[1]
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash FROM agent_credentials WHERE member_id = $1`, ag.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	want := hmacSHA256(oldKey, secret)
	if !bytes.Equal(stored, want) {
		t.Fatalf("stored Agent credential hash = %x, want HMAC-SHA256 %x", stored, want)
	}
	plainHash := sha256.Sum256([]byte(secret))
	if bytes.Equal(stored, plainHash[:]) {
		t.Fatal("Agent credential hash is a plain SHA-256 digest, want HMAC")
	}
	rotating := &Service{Store: st, HMACKeys: [][]byte{newKey, oldKey}}
	if _, err := rotating.AuthenticateKey(ctx, raw); err != nil {
		t.Fatalf("credential issued with previous HMAC key was not accepted during rotation: %v", err)
	}
	rotated, err := rotating.Rotate(ctx, owner.ID, ag.ID)
	if err != nil {
		t.Fatal(err)
	}
	rotatedSecret := strings.SplitN(rotated, ".", 2)[1]
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash FROM agent_credentials WHERE member_id = $1 AND revoked_at IS NULL`, ag.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, hmacSHA256(newKey, rotatedSecret)) {
		t.Fatal("rotated Agent credential was not hashed with the current HMAC key")
	}
}

func TestOAuthRefreshCredentialsRotateWithHMACAndRevokeOnReplay(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	oldKey := []byte("oauth-refresh-hmac-key-000000000001")
	newKey := []byte("oauth-refresh-hmac-key-000000000002")
	legacy := &Service{Store: st, HMACKeys: [][]byte{oldKey}}
	ag, _, err := legacy.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "oauth-refresh-agent", Source: "oauth", ExpiresAt: time.Now().UTC().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := legacy.CreateOAuthRefreshCredential(ctx, ag.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "ply_rt_") || !strings.Contains(raw, ".") {
		t.Fatalf("OAuth refresh credential format = %q, want ply_rt_ prefix and opaque secret", raw)
	}
	prefix := strings.SplitN(raw, ".", 2)[0]
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash FROM agent_credentials WHERE prefix = $1 AND kind = 'oauth_refresh'`, prefix).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, hmacSHA256(oldKey, raw)) {
		t.Fatalf("OAuth refresh hash = %x, want HMAC-SHA-256 of the complete token", stored)
	}
	rotating := &Service{Store: st, HMACKeys: [][]byte{newKey, oldKey}}
	credential, next, err := rotating.RotateOAuthRefresh(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if credential.MemberID != ag.ID || credential.Kind != "oauth_refresh" || next == raw {
		t.Fatalf("rotated OAuth credential = %+v next=%q", credential, next)
	}
	nextPrefix := strings.SplitN(next, ".", 2)[0]
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash FROM agent_credentials WHERE prefix = $1`, nextPrefix).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, hmacSHA256(newKey, next)) {
		t.Fatal("rotated OAuth refresh hash did not use the current HMAC key")
	}
	if _, _, err := rotating.RotateOAuthRefresh(ctx, raw); err == nil {
		t.Fatal("replayed OAuth refresh token was accepted")
	} else {
		assertAgentError(t, err, "invalid_grant")
	}
	var active int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_credentials WHERE family_id = (SELECT family_id FROM agent_credentials WHERE prefix = $1) AND revoked_at IS NULL`, prefix).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("OAuth refresh replay left %d active family credentials", active)
	}
}

func TestOAuthRefreshCredentialUsesRuntimeRefreshTTL(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	configured := 90 * time.Minute
	agents := &Service{
		Store: st, HMACKeys: [][]byte{[]byte("oauth-refresh-runtime-ttl-key-00001")},
		RefreshTTL: func(context.Context) (time.Duration, error) { return configured, nil },
	}
	ag, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "oauth-runtime-ttl-agent", Source: "oauth", ExpiresAt: time.Now().UTC().Add(3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := agents.CreateOAuthRefreshCredential(ctx, ag.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	if err := st.Pool.QueryRow(ctx, `SELECT expires_at FROM agent_credentials WHERE member_id = $1 AND kind = 'oauth_refresh'`, ag.ID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	remaining := time.Until(expires)
	if remaining < configured-time.Minute || remaining > configured+time.Minute {
		t.Fatalf("OAuth refresh expiry remaining = %s, want runtime TTL %s", remaining, configured)
	}
	if _, _, err := agents.RotateOAuthRefresh(ctx, raw); err != nil {
		t.Fatal(err)
	}
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func TestAgentDelegationDepthUsesConfiguredLimit(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	agents := &Service{Store: st, MaxDelegationDepth: 2}
	parent, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "depth-parent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: parent.ID, Name: "depth-child", ExpiresAt: time.Now().UTC().Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: child.ID, Name: "depth-grandchild", ExpiresAt: time.Now().UTC().Add(15 * time.Minute)}); err == nil {
		t.Fatal("Agent creation exceeded configured delegation depth")
	} else {
		assertAgentError(t, err, "VALIDATION_FAILED")
	}
}

func TestAgentGroupStructureIsDatabaseEnforced(t *testing.T) {
	ctx := context.Background()
	st, _, owner, spaceID := newAgentFixture(t)
	agents := &Service{Store: st}

	rootID := "grp_agent_structure_root"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, kind, status)
		VALUES ($1, $2, 'Standard root', 'standard', 'active')
	`, rootID, spaceID); err != nil {
		t.Fatal(err)
	}
	humanAgent, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "human-owner-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var humanParent *string
	if err := st.Pool.QueryRow(ctx, `SELECT parent_id FROM groups WHERE id = $1`, humanAgent.HomeGroupID).Scan(&humanParent); err != nil {
		t.Fatal(err)
	}
	if humanParent != nil {
		t.Fatalf("human-owned Agent group parent = %q, want top-level", *humanParent)
	}

	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, parent_id, kind, owner_member_id, status)
		VALUES ('grp_agent_structure_invalid_human', $1, 'Invalid human Agent group', $2, 'agents', $3, 'active')
	`, spaceID, rootID, owner.ID); err == nil {
		t.Fatal("database accepted a non-top-level human Agent group")
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, parent_id, kind, owner_member_id, status)
		VALUES ('grp_agent_structure_invalid_child', $1, 'Invalid Agent child', $2, 'agents', $3, 'active')
	`, spaceID, rootID, humanAgent.ID); err == nil {
		t.Fatal("database accepted an Agent group below a standard group")
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO groups (id, space_id, name, parent_id, kind, status)
		VALUES ('grp_agent_structure_invalid_standard', $1, 'Invalid standard child', $2, 'standard', 'active')
	`, spaceID, humanAgent.HomeGroupID); err == nil {
		t.Fatal("database accepted a standard group below an Agent group")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE groups SET parent_id = $1 WHERE id = $2`, rootID, humanAgent.HomeGroupID); err == nil {
		t.Fatal("database accepted moving an Agent group")
	}

	applicationID := "mem_agent_structure_application"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO members (id, space_id, name, kind, type, binding_policy, status, version)
		VALUES ($1, $2, 'Application owner', 'service', 'application', 'single', 'active', 1)
	`, applicationID, spaceID); err != nil {
		t.Fatal(err)
	}
	applicationAgent, _, err := agents.Create(ctx, CreateInput{OwnerMemberID: applicationID, Name: "application-owner-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var applicationParent *string
	if err := st.Pool.QueryRow(ctx, `SELECT parent_id FROM groups WHERE id = $1`, applicationAgent.HomeGroupID).Scan(&applicationParent); err != nil {
		t.Fatal(err)
	}
	if applicationParent != nil {
		t.Fatalf("application-owned Agent group parent = %q, want top-level", *applicationParent)
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

func TestExpiredAgentsAreTombstonedByRiverWorker(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	agents := &Service{Store: st}
	parent, parentKey, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "expired-parent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(ctx, CreateInput{OwnerMemberID: parent.ID, Name: "expired-child", ExpiresAt: time.Now().UTC().Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET expires_at = now() - interval '1 second' WHERE id = $1`, parent.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.Jobs.RegisterAgentExpiry(agents); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := st.Jobs.Start(workerCtx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := st.Jobs.Stop(stopCtx); err != nil {
			t.Fatalf("stop River worker: %v", err)
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var status string
		if err := st.Pool.QueryRow(ctx, `SELECT status FROM members WHERE id = $1`, parent.ID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "removed" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	assertMemberStatus(t, st, parent.ID, "removed")
	assertMemberStatus(t, st, child.ID, "removed")
	if _, err := agents.AuthenticateKey(ctx, parentKey); err == nil {
		t.Fatal("expired parent Agent credential remained usable")
	}
	if _, err := agents.AuthenticateKey(ctx, childKey); err == nil {
		t.Fatal("expired child Agent credential remained usable")
	}
	var auditCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'agent.expire' AND resource_id = $1`, parent.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expired Agent audit rows = %d, want 1", auditCount)
	}
}

func TestExpiredAgentCleanupRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	agents := &Service{Store: st}
	ag, key, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "expired-audit-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET expires_at = now() - interval '1 second' WHERE id = $1`, ag.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_expired_agent_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'expired Agent audit insert rejected by test'; END;
		$$;
		CREATE TRIGGER test_reject_expired_agent_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_expired_agent_audit();
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := agents.ExpireAgents(ctx); err == nil {
		t.Fatal("expired Agent cleanup succeeded despite audit failure")
	}
	assertMemberStatus(t, st, ag.ID, "active")
	if _, err := agents.AuthenticateKey(ctx, key); err != nil {
		t.Fatalf("expired Agent credential changed after rollback: %v", err)
	}
}

func TestAgentStatusMutationRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	st, _, owner, _ := newAgentFixture(t)
	agents := &Service{Store: st}
	ag, key, err := agents.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "audit-rollback-agent", ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_agent_audit_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'agent audit insert rejected by test'; END;
		$$;
		CREATE TRIGGER test_reject_agent_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_agent_audit_insert();
	`); err != nil {
		t.Fatal(err)
	}
	if err := agents.Stop(ctx, owner.ID, ag.ID); err == nil {
		t.Fatal("agent stop succeeded despite audit failure")
	}
	assertMemberStatus(t, st, ag.ID, "active")
	if _, err := agents.AuthenticateKey(ctx, key); err != nil {
		t.Fatalf("agent credential became unusable after audit failure: %v", err)
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
