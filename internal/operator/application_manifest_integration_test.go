package operator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
)

func manifestReviewProof(t *testing.T, f *applicationSuspensionFixture, operation string, permissions []string) []byte {
	t.Helper()
	value := map[string]any{"application_id": f.application.ID}
	if permissions != nil {
		value["manifest_permissions"] = permissions
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if _, err := f.store.Pool.Exec(context.Background(), `UPDATE operator_sessions SET step_up_operation = $1,
		step_up_digest = $2, step_up_expires_at = now() + interval '5 minutes' WHERE user_id = 'usr_stop_operator'`, operation, digest[:]); err != nil {
		t.Fatal(err)
	}
	return digest[:]
}

func publicManifestAuthority(t *testing.T, f *applicationSuspensionFixture, allowed ...bool) {
	t.Helper()
	for i, installation := range f.installations {
		for _, authorizer := range f.authorizers {
			decision, _, err := authorizer.Check(context.Background(), authorization.CheckRequest{
				MemberID: installation.MemberID, Permission: "auth.agents:create", ResourceSpace: installation.SpaceID,
			})
			if err != nil || (decision.Effect == engine.Allow) != allowed[i] {
				t.Fatalf("customer %d authority=%s code=%s error=%v", i, decision.Effect, decision.Code, err)
			}
		}
	}
}

func submitPublicManifest(t *testing.T, f *applicationSuspensionFixture, permissions []string) application.PublishedApplication {
	t.Helper()
	out, err := f.applications.Update(context.Background(), f.owners[0].ID, f.application.ID, application.UpdateInput{ManifestPermissions: &permissions})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func publishPublicManifest(t *testing.T, f *applicationSuspensionFixture, permissions []string) PublicApplicationReview {
	t.Helper()
	digest := manifestReviewProof(t, f, "ops.applications.approve", permissions)
	out, err := f.operators.ApprovePublicApplication(context.Background(), f.operatorToken, f.application.ID, permissions, digest)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPublicManifestReviewPreservesLiveVersionAndRequiresCustomerReapproval(t *testing.T) {
	f := newApplicationSuspensionFixture(t)
	ctx := context.Background()
	_, key, err := f.applications.CreateManagedKey(ctx, f.owners[0].ID, f.application.ID, application.CreateManagedKeyInput{
		Name: "manifest-lifecycle", Grants: []string{"auth.agents:create", "auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	publicManifestAuthority(t, f, true, true)
	requested := []string{"auth.audit:write", "auth.authz:check"}
	pending := submitPublicManifest(t, f, requested)
	_, err = f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, requested, nil)
	assertOperatorError(t, err, "STEP_UP_REQUIRED")
	assertOperatorError(t, f.operators.RejectPublicApplication(ctx, f.operatorToken, f.application.ID, nil), "STEP_UP_REQUIRED")
	if pending.ReviewStatus != "approved" || !slices.Equal(pending.PendingManifestPermissions, requested) || !slices.Contains(pending.ManifestPermissions, "auth.agents:create") {
		t.Fatal("pending review replaced the effective approved manifest")
	}
	client, err := f.applications.OAuthClient(ctx, f.application.ClientID)
	if err != nil || !slices.Contains(client.AllowedScopes, "auth.agents:create") || slices.Contains(client.AllowedScopes, "auth.audit:write") {
		t.Fatal("pending review changed the runtime OAuth scope")
	}
	if _, _, err := f.applications.CreateManagedKey(ctx, f.owners[0].ID, f.application.ID, application.CreateManagedKeyInput{
		Name: "unreviewed-scope", Grants: []string{"auth.audit:write"}, ExpiresAt: time.Now().Add(time.Hour),
	}); err == nil {
		t.Fatal("a pending manifest permission became a usable key grant")
	} else {
		assertOperatorError(t, err, "GRANT_EXCEEDS_OWNER")
	}
	digest := manifestReviewProof(t, f, "ops.applications.reject", nil)
	if err := f.operators.RejectPublicApplication(ctx, f.operatorToken, f.application.ID, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := f.applications.OAuthClient(ctx, f.application.ClientID); err != nil {
		t.Fatal("rejecting an update disabled the previously approved client")
	}
	publicManifestAuthority(t, f, true, true)
	submitPublicManifest(t, f, requested)
	approved := publishPublicManifest(t, f, []string{"auth.authz:check"})
	if !slices.Equal(approved.ManifestPermissions, []string{"auth.authz:check"}) || len(approved.PendingManifestPermissions) != 0 {
		t.Fatal("operator subset approval did not publish its exact manifest")
	}
	publicManifestAuthority(t, f, false, false)
	for _, descendant := range f.agentMembers {
		if descendant.OwnerMemberID != f.installations[0].MemberID && descendant.OwnerMemberID != f.installations[1].MemberID {
			continue
		}
		for _, authorizer := range f.authorizers {
			decision, _, err := authorizer.Check(ctx, authorization.CheckRequest{MemberID: descendant.ID, Permission: "auth.agents:create", ResourceSpace: descendant.SpaceID})
			if err != nil || decision.Code != "OWNER_ENVELOPE_EXCLUDED" {
				t.Fatalf("application-owned Agent retained removed authority: %s error=%v", decision.Code, err)
			}
		}
	}
	assertKey := func() {
		t.Helper()
		current, err := f.applications.AuthenticateKey(ctx, key.Value())
		if err != nil || !slices.Equal(current.Scopes, []string{"auth.authz:check"}) {
			t.Fatal("removed key grants were retained or restored")
		}
	}
	assertKey()
	client, err = f.applications.OAuthClient(ctx, f.application.ClientID)
	if err != nil || !slices.Equal(client.AllowedScopes, []string{"auth.authz:check"}) {
		t.Fatal("approved manifest did not update OAuth scope limits")
	}
	expanded := []string{"auth.agents:create", "auth.authz:check"}
	submitPublicManifest(t, f, expanded)
	publishPublicManifest(t, f, expanded)
	publicManifestAuthority(t, f, false, false)
	assertKey()
	if _, err := f.store.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, f.owners[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.applications.ApproveInstallationManifest(ctx, f.owners[0].ID, f.owners[0].SpaceID, f.installations[0].ID); err == nil {
		t.Fatal("customer approved expanded authority without assignment rights")
	} else {
		assertOperatorError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	}
	publicManifestAuthority(t, f, false, false)
	if _, err := f.store.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = NULL WHERE holder_member_id = $1`, f.owners[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.applications.ApproveInstallationManifest(ctx, f.owners[0].ID, f.owners[0].SpaceID, f.installations[0].ID); err != nil {
		t.Fatal(err)
	}
	publicManifestAuthority(t, f, true, false)
	assertKey()
	var snapshots int
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'application.installation.manifest.narrow'
		AND application_id = $1 AND actor_type = 'operator_session' AND user_id = 'usr_stop_operator'
		AND member_type = 'application' AND space_id IN ($2, $3)`, f.application.ID, f.owners[0].SpaceID, f.owners[1].SpaceID).Scan(&snapshots); err != nil || snapshots != 2 {
		t.Fatalf("customer audit snapshots=%d error=%v", snapshots, err)
	}
	var serialized string
	if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a))::text FROM audit_logs a
		WHERE action IN ('application.update','ops.application.approve','ops.application.reject','application.installation.manifest.narrow')`).Scan(&serialized); err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{key.Value(), f.operatorToken, "ply_sk_", "ply_ops_", "ply_ag_"} {
		if strings.Contains(serialized, sensitive) {
			t.Fatal("manifest review audit exposed a credential")
		}
	}
}

func TestPublicGroupManifestReviewRequiresCustomerReapproval(t *testing.T) {
	ctx := context.Background()
	f := newApplicationSuspensionFixture(t)
	for i, scope := range []string{"group", "group_tree"} {
		owner := f.owners[i]
		if _, err := f.applications.ChangeInstallationStatus(ctx, owner.ID, owner.SpaceID, f.installations[i].ID, "uninstall"); err != nil {
			t.Fatal(err)
		}
		anchor := fmt.Sprintf("grp_public_manifest_%d", i)
		if _, err := f.store.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name) VALUES ($1, $2, 'Manifest anchor')`, anchor, owner.SpaceID); err != nil {
			t.Fatal(err)
		}
		installed, err := f.applications.Install(ctx, owner.ID, f.application.ID, owner.SpaceID, scope, anchor)
		if err != nil {
			t.Fatal(err)
		}
		f.installations[i] = installed
	}
	check := func(want ...bool) {
		t.Helper()
		for i, installed := range f.installations {
			for _, authz := range f.authorizers {
				decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: installed.MemberID, Permission: "auth.agents:create",
					ResourceSpace: installed.SpaceID, ResourceGroup: installed.AnchorGroupID})
				if err != nil || (decision.Effect == engine.Allow) != want[i] {
					t.Fatalf("group customer %d: %s/%s error=%v", i, decision.Effect, decision.Code, err)
				}
			}
		}
	}
	check(true, true)
	_, raw, err := f.applications.CreateManagedKey(ctx, f.owners[0].ID, f.application.ID, application.CreateManagedKeyInput{
		Name: "group-manifest-key", Grants: []string{"auth.agents:create", "auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.applications.ChangeInstallationStatus(ctx, f.owners[1].ID, f.owners[1].SpaceID, f.installations[1].ID, "suspend"); err != nil {
		t.Fatal(err)
	}
	check(true, false)
	narrowed := []string{"auth.authz:check"}
	submitPublicManifest(t, f, narrowed)
	check(true, false)
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_public_group_manifest() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.installation.manifest.narrow' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_public_group_manifest BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_public_group_manifest()`); err != nil {
		t.Fatal(err)
	}
	digest := manifestReviewProof(t, f, "ops.applications.approve", narrowed)
	if _, err := f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, narrowed, digest); err == nil {
		t.Fatal("group manifest shrink committed without audit")
	}
	check(true, false)
	key, err := f.applications.AuthenticateKey(ctx, raw.Value())
	if err != nil || !slices.Contains(key.Scopes, "auth.agents:create") {
		t.Fatal("failed group manifest review changed the key")
	}
	if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_public_group_manifest ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	publishPublicManifest(t, f, narrowed)
	check(false, false)
	for _, installed := range f.installations {
		var approved []byte
		var permissions, audits int
		if err := f.store.Pool.QueryRow(ctx, `SELECT approved_permissions FROM application_installations WHERE id = $1`, installed.ID).Scan(&approved); err != nil || string(approved) != `["auth.authz:check"]` {
			t.Fatalf("group approval not narrowed: %s error=%v", approved, err)
		}
		if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp JOIN application_installations i ON i.role_id = rp.role_id WHERE i.id = $1`, installed.ID).Scan(&permissions); err != nil || permissions != 1 {
			t.Fatalf("group role not narrowed: count=%d error=%v", permissions, err)
		}
		if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'application.installation.manifest.narrow'
			AND resource_id = $1 AND resource_group_id = $2 AND space_id = $3 AND application_id = $4`, installed.ID, installed.AnchorGroupID, installed.SpaceID, installed.ApplicationID).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("group manifest audit lost resource scope: count=%d error=%v", audits, err)
		}
	}
	if _, err := f.applications.ChangeInstallationStatus(ctx, f.owners[1].ID, f.owners[1].SpaceID, f.installations[1].ID, "resume"); err != nil {
		t.Fatal(err)
	}
	check(false, false)
	expanded := []string{"auth.agents:create", "auth.authz:check"}
	submitPublicManifest(t, f, expanded)
	publishPublicManifest(t, f, expanded)
	check(false, false)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_envelopes (group_id) VALUES ($1)`, f.installations[0].AnchorGroupID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_envelope_entries (group_id, permission_id, mode)
		SELECT $1, id, 'delegate' FROM permissions WHERE key <> 'auth.agents:create'`, f.installations[0].AnchorGroupID); err != nil {
		t.Fatal(err)
	}
	_, err = f.applications.ApproveInstallationManifest(ctx, f.owners[0].ID, f.owners[0].SpaceID, f.installations[0].ID)
	assertOperatorError(t, err, "AUTHORITY_DELTA_NOT_COVERED")
	check(false, false)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_envelope_entries (group_id, permission_id, mode)
		SELECT $1, id, 'assign' FROM permissions WHERE key = 'auth.agents:create'`, f.installations[0].AnchorGroupID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.applications.ApproveInstallationManifest(ctx, f.owners[0].ID, f.owners[0].SpaceID, f.installations[0].ID); err != nil {
		t.Fatal(err)
	}
	check(true, false)
	key, err = f.applications.AuthenticateKey(ctx, raw.Value())
	if err != nil || !slices.Equal(key.Scopes, []string{"auth.authz:check"}) {
		t.Fatal("group customer approval restored a removed key grant")
	}
}

func TestPublicManifestReviewRollsBackEveryCustomerAndStepUpOnAuditFailure(t *testing.T) {
	for _, action := range []string{"ops.application.approve", "application.installation.manifest.narrow"} {
		t.Run(action, func(t *testing.T) {
			f := newApplicationSuspensionFixture(t)
			ctx := context.Background()
			permissions := []string{"auth.authz:check"}
			submitPublicManifest(t, f, permissions)
			publicManifestAuthority(t, f, true, true)
			_, key, err := f.applications.CreateManagedKey(ctx, f.owners[0].ID, f.application.ID, application.CreateManagedKeyInput{
				Name: "rollback", Grants: []string{"auth.agents:create"}, ExpiresAt: time.Now().Add(time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			versions := make([]int64, len(f.owners))
			for i, owner := range f.owners {
				if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, owner.SpaceID).Scan(&versions[i]); err != nil {
					t.Fatal(err)
				}
			}
			digest := manifestReviewProof(t, f, "ops.applications.approve", permissions)
			// The action comes only from this fixed test table.
			if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_manifest_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN IF NEW.action = '`+action+`' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
				CREATE TRIGGER reject_manifest_review_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_manifest_review_audit()`); err != nil {
				t.Fatal(err)
			}
			if _, err := f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, permissions, digest); err == nil {
				t.Fatal("manifest published without durable audit")
			}
			publicManifestAuthority(t, f, true, true)
			current, err := f.applications.AuthenticateKey(ctx, key.Value())
			if err != nil || !slices.Equal(current.Scopes, []string{"auth.agents:create"}) {
				t.Fatal("failed review trimmed a key grant")
			}
			for i, owner := range f.owners {
				var version int64
				if err := f.store.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, owner.SpaceID).Scan(&version); err != nil || version != versions[i] {
					t.Fatalf("failed review changed policy version: before=%d after=%d error=%v", versions[i], version, err)
				}
			}
			var effective, pending, status string
			if err := f.store.Pool.QueryRow(ctx, `SELECT manifest_permissions::text, pending_manifest_permissions::text, review_status
				FROM applications WHERE id = $1`, f.application.ID).Scan(&effective, &pending, &status); err != nil || !strings.Contains(effective, "auth.agents:create") || pending != `["auth.authz:check"]` || status != "approved" {
				t.Fatalf("failed review changed manifest=%s pending=%s status=%s error=%v", effective, pending, status, err)
			}
			var count int
			if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'application.installation.manifest.narrow'`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed review left customer audit events=%d error=%v", count, err)
			}
			if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_manifest_review_audit ON audit_logs`); err != nil {
				t.Fatal(err)
			}
			if _, err := f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, permissions, digest); err != nil {
				t.Fatalf("failed review consumed its step-up: %v", err)
			}
			publicManifestAuthority(t, f, false, false)
		})
	}
}

func TestPublicManifestReviewSerializesWithNewInstallationsAndKeys(t *testing.T) {
	f := newApplicationSuspensionFixture(t)
	ctx := context.Background()
	space, owner, err := f.authorizers[0].CreateSpace(ctx, "usr_stop_owner_0", "Concurrent customer", "manifest-concurrent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_manifest_concurrent', $1, '["auth.applications:manage"]'::jsonb, $2, 'space', $1, 'system')`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	permissions := []string{"auth.authz:check"}
	submitPublicManifest(t, f, permissions)
	digest := manifestReviewProof(t, f, "ops.applications.approve", permissions)
	start := make(chan struct{})
	approval, installation, key := make(chan error, 1), make(chan error, 1), make(chan error, 1)
	go func() {
		<-start
		_, err := f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, permissions, digest)
		approval <- err
	}()
	go func() {
		<-start
		_, err := f.applications.InstallSpace(ctx, owner.ID, f.application.ID, space.ID)
		installation <- err
	}()
	go func() {
		<-start
		_, _, err := f.applications.CreateManagedKey(ctx, f.owners[0].ID, f.application.ID, application.CreateManagedKeyInput{
			Name: "concurrent", Grants: []string{"auth.agents:create"}, ExpiresAt: time.Now().Add(time.Hour),
		})
		key <- err
	}()
	close(start)
	if err := <-approval; err != nil {
		t.Fatal(err)
	}
	if err := <-installation; err != nil {
		t.Fatal(err)
	}
	if err := <-key; err != nil {
		assertOperatorError(t, err, "GRANT_EXCEEDS_OWNER")
	}
	var stale int
	if err := f.store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM application_installations WHERE application_id = $1 AND approved_permissions ? 'auth.agents:create') +
		(SELECT count(*) FROM api_keys WHERE application_id = $1 AND scopes ? 'auth.agents:create')`, f.application.ID).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("concurrent create escaped manifest narrowing: count=%d error=%v", stale, err)
	}
}

func TestPublicManifestReviewRechecksDirectoryAndPendingRequest(t *testing.T) {
	f := newApplicationSuspensionFixture(t)
	ctx := context.Background()
	permissions := []string{"auth.audit:write", "auth.authz:check"}
	submitPublicManifest(t, f, permissions)
	outside := []string{"auth.agents:create"}
	digest := manifestReviewProof(t, f, "ops.applications.approve", outside)
	_, err := f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, outside, digest)
	assertOperatorError(t, err, "VALIDATION_FAILED")
	for _, status := range []string{"disabled", "deprecated"} {
		if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'auth.audit:write'`, status); err != nil {
			t.Fatal(err)
		}
		digest = manifestReviewProof(t, f, "ops.applications.approve", permissions)
		_, err := f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, permissions, digest)
		assertOperatorError(t, err, "PERMISSION_DISABLED")
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'active', principal_kinds = '["human"]'::jsonb WHERE key = 'auth.audit:write'`); err != nil {
		t.Fatal(err)
	}
	digest = manifestReviewProof(t, f, "ops.applications.approve", permissions)
	_, err = f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, permissions, digest)
	assertOperatorError(t, err, "VALIDATION_FAILED")
	publicManifestAuthority(t, f, true, true)
	if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human","agent","application"]'::jsonb WHERE key = 'auth.audit:write';
		UPDATE permissions SET status = 'deprecated' WHERE key = 'auth.authz:check'`); err != nil {
		t.Fatal(err)
	}
	// Retaining an existing deprecated approval is different from adding one.
	publishPublicManifest(t, f, permissions)
	digest = manifestReviewProof(t, f, "ops.applications.approve", permissions)
	_, err = f.operators.ApprovePublicApplication(ctx, f.operatorToken, f.application.ID, permissions, digest)
	assertOperatorError(t, err, "CONFLICT")
	digest = manifestReviewProof(t, f, "ops.applications.reject", nil)
	assertOperatorError(t, f.operators.RejectPublicApplication(ctx, f.operatorToken, f.application.ID, digest), "CONFLICT")
}

func TestPublicManifestReviewNarrowsSuspendedAndTreeInstallations(t *testing.T) {
	f := newApplicationSuspensionFixture(t)
	ctx := context.Background()
	space, owner, err := f.authorizers[0].CreateSpace(ctx, "usr_stop_owner_0", "Tree manifest customer", "manifest-tree")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_manifest_tree', $1, '["auth.applications:manage"]'::jsonb, $2, 'space', $1, 'system')`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	installed, err := f.applications.Install(ctx, owner.ID, f.application.ID, space.ID, "space_tree", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id)
		VALUES ('spc_manifest_tree_leaf', 'Leaf', 'manifest-tree-leaf', $1)`, space.ID); err != nil {
		t.Fatal(err)
	}
	checkLeaf := func(want engine.Effect) {
		t.Helper()
		for _, authorizer := range f.authorizers {
			decision, _, err := authorizer.Check(ctx, authorization.CheckRequest{
				MemberID: installed.MemberID, Permission: "auth.agents:create", ResourceSpace: "spc_manifest_tree_leaf",
			})
			if err != nil || decision.Effect != want {
				t.Fatalf("tree manifest authority=%s error=%v", decision.Effect, err)
			}
		}
	}
	checkLeaf(engine.Allow)
	if _, err := f.applications.ChangeInstallationStatus(ctx, f.owners[1].ID, f.owners[1].SpaceID, f.installations[1].ID, "suspend"); err != nil {
		t.Fatal(err)
	}
	permissions := []string{"auth.authz:check"}
	submitPublicManifest(t, f, permissions)
	publishPublicManifest(t, f, permissions)
	checkLeaf(engine.Deny)
	if _, err := f.applications.ChangeInstallationStatus(ctx, f.owners[1].ID, f.owners[1].SpaceID, f.installations[1].ID, "resume"); err != nil {
		t.Fatal(err)
	}
	publicManifestAuthority(t, f, false, false)
	items, err := f.applications.ListInstallations(ctx, f.owners[1].ID, f.owners[1].SpaceID)
	if err != nil || len(items) != 1 || !slices.Equal(items[0].ApprovedPermissions, permissions) {
		t.Fatal("resuming a suspended installation restored removed approvals")
	}
}
