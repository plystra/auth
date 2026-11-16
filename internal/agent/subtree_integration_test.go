package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/store"
)

func TestAgentLifecyclePreservesSiblingDelegationTrees(t *testing.T) {
	for _, operation := range []string{"stop", "delete", "expire"} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%t", operation, nested), func(t *testing.T) {
				ctx := context.Background()
				st, _, owner, spaceID := newAgentFixture(t)
				svc := &Service{Store: st}
				expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
				var members []Agent
				var keys []string
				for i, ownerIndex := range []int{-1, 0, 1, -1, 3, 0, 5} {
					ownerID := owner.ID
					if ownerIndex >= 0 {
						ownerID = members[ownerIndex].ID
					}
					created, key, err := svc.Create(ctx, CreateInput{OwnerMemberID: ownerID, Name: fmt.Sprintf("branch-%d", i), ExpiresAt: expiresAt})
					if err != nil {
						t.Fatal(err)
					}
					members, keys = append(members, created), append(keys, key)
					if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
						VALUES ($1, $2, '["self:read"]'::jsonb, $3, 'space', $2, $4)`, fmt.Sprintf("grt_branch_%d", i), spaceID, created.ID, owner.ID); err != nil {
						t.Fatal(err)
					}
				}
				targetIndex := 0
				if nested {
					targetIndex = 1
				}
				target := members[targetIndex]
				if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
					(id, space_id, permission_keys, grantee_group_id, scope, anchor_space_id, granted_by)
					VALUES ('grt_shared_agents', $1, '["self:read"]'::jsonb, $2, 'space', $1, $3)`, spaceID, target.HomeGroupID, owner.ID); err != nil {
					t.Fatal(err)
				}
				if operation == "expire" {
					if _, err := st.Pool.Exec(ctx, `UPDATE members SET expires_at = now() - interval '1 second' WHERE id = $1`, target.ID); err != nil {
						t.Fatal(err)
					}
				}
				versions := make([]int64, len(members))
				for i, member := range members {
					versions[i] = readAgentVersion(t, st, member.ID)
				}
				spaceVersion := readSpacePolicyVersion(t, st, spaceID)
				var err error
				switch operation {
				case "stop":
					err = svc.Stop(ctx, owner.ID, target.ID)
				case "delete":
					err = svc.Delete(ctx, owner.ID, target.ID)
				case "expire":
					var count int
					count, err = svc.ExpireAgents(ctx)
					if err == nil && count != 1 {
						t.Fatalf("expired roots = %d, want 1", count)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				for i, member := range members {
					affected := i == 1 || i == 2 || !nested && (i == 0 || i >= 5)
					status := "active"
					if affected {
						status = "removed"
						if operation == "stop" {
							status = "suspended"
						}
					}
					assertMemberStatus(t, st, member.ID, status)
					_, keyErr := svc.AuthenticateKey(ctx, keys[i])
					if affected == (keyErr == nil) {
						t.Fatalf("member %d credential result = %v, affected=%t", i, keyErr, affected)
					}
					version := readAgentVersion(t, st, member.ID)
					if affected && version <= versions[i] || !affected && version != versions[i] {
						t.Fatalf("member %d version = %d, previous=%d, affected=%t", i, version, versions[i], affected)
					}
					var revoked bool
					if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM authorization_grants WHERE id = $1`, fmt.Sprintf("grt_branch_%d", i)).Scan(&revoked); err != nil {
						t.Fatal(err)
					}
					if revoked != (affected && operation != "stop") {
						t.Fatalf("member %d grant revoked=%t, affected=%t", i, revoked, affected)
					}
				}
				var homeStatus string
				var sharedRevoked bool
				if err := st.Pool.QueryRow(ctx, `SELECT status FROM groups WHERE id = $1`, target.HomeGroupID).Scan(&homeStatus); err != nil {
					t.Fatal(err)
				}
				if err := st.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM authorization_grants WHERE id = 'grt_shared_agents'`).Scan(&sharedRevoked); err != nil {
					t.Fatal(err)
				}
				if homeStatus != "active" || sharedRevoked {
					t.Fatalf("target's containing group was modified: status=%s grant_revoked=%t", homeStatus, sharedRevoked)
				}
				if current := readSpacePolicyVersion(t, st, spaceID); current != spaceVersion {
					t.Fatalf("local Agent mutation changed Space policy version: %d -> %d", spaceVersion, current)
				}
			})
		}
	}
}

func TestAgentCreationKeepsSpacePolicyVersion(t *testing.T) {
	ctx := context.Background()
	st, _, owner, spaceID := newAgentFixture(t)
	version := readSpacePolicyVersion(t, st, spaceID)
	created, _, err := (&Service{Store: st}).Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "local-agent"})
	if err != nil {
		t.Fatal(err)
	}
	if current := readAgentVersion(t, st, created.ID); current != created.Version {
		t.Fatalf("created Agent response version=%d, stored=%d", created.Version, current)
	}
	if current := readSpacePolicyVersion(t, st, spaceID); current != version {
		t.Fatalf("Agent creation invalidated unrelated Space authority: %d -> %d", version, current)
	}
}

func TestAgentGrantMutationVersionsBothAffectedPrincipals(t *testing.T) {
	ctx := context.Background()
	st, _, owner, spaceID := newAgentFixture(t)
	svc := &Service{Store: st}
	first, _, err := svc.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "grant-first"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := svc.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "grant-second"})
	if err != nil {
		t.Fatal(err)
	}
	spaceVersion := readSpacePolicyVersion(t, st, spaceID)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_local_versions', $1, '["self:read"]'::jsonb, $2, 'space', $1, $3)`, spaceID, first.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	firstVersion := readAgentVersion(t, st, first.ID)
	if firstVersion <= first.Version || readAgentVersion(t, st, second.ID) != second.Version {
		t.Fatal("grant creation did not invalidate only its Agent grantee")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET grantee_member_id = $1 WHERE id = 'grt_local_versions'`, second.ID); err != nil {
		t.Fatal(err)
	}
	if readAgentVersion(t, st, first.ID) <= firstVersion || readAgentVersion(t, st, second.ID) <= second.Version {
		t.Fatal("grant reassignment failed to invalidate both the old and new grantee")
	}
	if readSpacePolicyVersion(t, st, spaceID) != spaceVersion {
		t.Fatal("Agent grant mutation invalidated unrelated Space authority")
	}
}

func TestAgentCredentialChangesKeepVersionsLocal(t *testing.T) {
	ctx := context.Background()
	st, _, owner, spaceID := newAgentFixture(t)
	svc := &Service{Store: st}
	selected, key, err := svc.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "credential-selected", Source: "oauth"})
	if err != nil {
		t.Fatal(err)
	}
	sibling, _, err := svc.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "credential-sibling"})
	if err != nil {
		t.Fatal(err)
	}
	version := readAgentVersion(t, st, selected.ID)
	spaceVersion, ownerVersion := readSpacePolicyVersion(t, st, spaceID), readAgentVersion(t, st, owner.ID)
	assertLocalChange := func(t *testing.T) {
		t.Helper()
		next := readAgentVersion(t, st, selected.ID)
		if next <= version {
			t.Fatalf("credential change did not increment Agent version: %d -> %d", version, next)
		}
		version = next
		if readAgentVersion(t, st, sibling.ID) != sibling.Version || readAgentVersion(t, st, owner.ID) != ownerVersion || readSpacePolicyVersion(t, st, spaceID) != spaceVersion {
			t.Fatal("credential change invalidated an independent principal or Space")
		}
	}
	if _, err := svc.AuthenticateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if readAgentVersion(t, st, selected.ID) != version {
		t.Fatal("key usage timestamp invalidated policy cache")
	}
	if _, err := svc.Rotate(ctx, owner.ID, selected.ID); err != nil {
		t.Fatal(err)
	}
	assertLocalChange(t)
	raw, err := svc.CreateOAuthRefreshCredential(ctx, selected.ID, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	assertLocalChange(t)
	_, next, err := svc.RotateOAuthRefresh(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	assertLocalChange(t)
	if _, _, err := svc.RotateOAuthRefresh(ctx, raw); err == nil {
		t.Fatal("refresh replay was accepted")
	}
	assertLocalChange(t)
	if found, err := svc.RevokeOAuthRefreshToken(ctx, next); err != nil || !found {
		t.Fatalf("refresh revocation: found=%t error=%v", found, err)
	}
	assertLocalChange(t)
}

func TestOAuthCredentialMutationLocksMembersBeforeCredentials(t *testing.T) {
	for _, operation := range []string{"refresh", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			st, _, owner, _ := newAgentFixture(t)
			svc := &Service{Store: st}
			parent, _, err := svc.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "locked-oauth-parent", Source: "oauth"})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := svc.CreateOAuthRefreshCredential(ctx, parent.ID, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			ready, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseTx := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseTx()
			mutationDone := make(chan error, 1)
			go func() {
				mutationDone <- st.InTx(ctx, func(q *db.Queries) error {
					if err := member.LockChainsTx(ctx, q, parent.ID); err != nil {
						return err
					}
					close(ready)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					return member.SetAgentSubtreeStatusTx(ctx, q, parent.ID, "suspended")
				})
			}()
			select {
			case <-ready:
			case err := <-mutationDone:
				t.Fatalf("member locking failed: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			credentialDone := make(chan error, 1)
			go func() {
				var err error
				if operation == "refresh" {
					_, _, err = svc.RotateOAuthRefresh(ctx, raw)
				} else {
					_, err = svc.RevokeOAuthRefreshToken(ctx, raw)
				}
				credentialDone <- err
			}()
			for {
				var query string
				err := st.Pool.QueryRow(ctx, `SELECT COALESCE((SELECT query FROM pg_stat_activity
					WHERE datname = current_database() AND wait_event_type = 'Lock' LIMIT 1), '')`).Scan(&query)
				if err != nil {
					t.Fatal(err)
				}
				if query != "" {
					if !strings.HasPrefix(query, "-- name: LockMemberForAuthorization") {
						t.Fatalf("credential operation locked credentials before members: %s", query)
					}
					break
				}
				select {
				case err := <-credentialDone:
					t.Fatalf("credential operation did not wait for member lock: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			releaseTx()
			if err := <-mutationDone; err != nil {
				t.Fatalf("revocation failed or deadlocked: %v", err)
			}
			err = <-credentialDone
			if operation == "refresh" {
				assertAgentError(t, err, "invalid_grant")
			} else if err != nil {
				t.Fatalf("idempotent credential revocation failed: %v", err)
			}
		})
	}
}

func TestAgentCreationSerializesWithAncestorRevocation(t *testing.T) {
	for _, status := range []string{"suspended", "removed"} {
		for _, rollback := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/rollback=%t", status, rollback), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				st, _, owner, _ := newAgentFixture(t)
				svc := &Service{Store: st}
				parent, _, err := svc.Create(ctx, CreateInput{OwnerMemberID: owner.ID, Name: "concurrent-parent"})
				if err != nil {
					t.Fatal(err)
				}
				child, _, err := svc.Create(ctx, CreateInput{OwnerMemberID: parent.ID, Name: "concurrent-owner", ExpiresAt: parent.ExpiresAt})
				if err != nil {
					t.Fatal(err)
				}
				ready, release := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				releaseTx := func() { releaseOnce.Do(func() { close(release) }) }
				defer releaseTx()
				mutationDone := make(chan error, 1)
				rollbackErr := errors.New("test rollback")
				go func() {
					mutationDone <- st.InTx(ctx, func(q *db.Queries) error {
						if err := member.SetAgentSubtreeStatusTx(ctx, q, parent.ID, status); err != nil {
							return err
						}
						close(ready)
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
						if rollback {
							return rollbackErr
						}
						return nil
					})
				}()
				select {
				case <-ready:
				case err := <-mutationDone:
					t.Fatalf("revocation did not reach barrier: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				creationDone := make(chan error, 1)
				go func() {
					_, _, err := svc.Create(ctx, CreateInput{OwnerMemberID: child.ID, Name: "concurrent-child", ExpiresAt: child.ExpiresAt})
					creationDone <- err
				}()
				for {
					var blocked bool
					if err := st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
						WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%members%')`).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked {
						break
					}
					select {
					case err := <-creationDone:
						t.Fatalf("creation did not wait for ancestor revocation: %v", err)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				releaseTx()
				if err := <-mutationDone; rollback && !errors.Is(err, rollbackErr) || !rollback && err != nil {
					t.Fatalf("revocation result: %v", err)
				}
				err = <-creationDone
				if rollback {
					if err != nil {
						t.Fatalf("creation failed after revocation rollback: %v", err)
					}
				} else {
					assertAgentError(t, err, "OWNER_INACTIVE")
				}
			})
		}
	}
}

func readAgentVersion(t *testing.T, st *store.Store, memberID string) int64 {
	t.Helper()
	var version int64
	if err := st.Pool.QueryRow(context.Background(), `SELECT version FROM members WHERE id = $1`, memberID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func readSpacePolicyVersion(t *testing.T, st *store.Store, spaceID string) int64 {
	t.Helper()
	var version int64
	if err := st.Pool.QueryRow(context.Background(), `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}
