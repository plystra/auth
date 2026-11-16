package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/security"
)

func TestPublicManifestUpdateHTTPPreservesApprovedVersionAndChecksPublisher(t *testing.T) {
	ctx := context.Background()
	st, _, apps, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
	if _, err := st.Pool.Exec(ctx, `UPDATE applications SET visibility = 'public', review_status = 'approved' WHERE id = $1`, appID); err != nil {
		t.Fatal(err)
	}
	token := manifestToken(t, sessions, ownerID)
	response := patchApplication(t, handler, appID, token, `{"manifest_permissions":["auth.authz:check","auth.tokens:introspect"]}`)
	var result struct {
		Data application.PublishedApplication `json:"data"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil ||
		result.Data.ReviewStatus != "approved" || !slices.Equal(result.Data.ManifestPermissions, []string{"auth.authz:check"}) || len(result.Data.PendingManifestPermissions) != 2 {
		t.Fatalf("public pending manifest response status=%d", response.Code)
	}
	created, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{
		OwnerMemberID: ownerID, Name: "Public manifest manager", ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, ownerID, created.ID, "auth.applications:manage")
	access, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	if got := patchApplication(t, handler, appID, access.AccessToken, `{"manifest_permissions":["auth.authz:check","auth.audit:write"]}`); got.Code != http.StatusOK {
		t.Fatalf("Agent could not submit a public manifest: status=%d", got.Code)
	}
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_public_manifest_submit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.update' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_public_manifest_submit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_public_manifest_submit()`); err != nil {
		t.Fatal(err)
	}
	if got := patchApplication(t, handler, appID, token, `{"name":"Must roll back","manifest_permissions":["auth.tokens:introspect"]}`); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("public manifest saved without durable audit: status=%d", got.Code)
	}
	listed, err := apps.ListPublished(ctx, spaceID)
	if err != nil || len(listed) != 1 || listed[0].Name != "Billing" || !slices.Equal(listed[0].PendingManifestPermissions, []string{"auth.audit:write", "auth.authz:check"}) {
		t.Fatal("failed public update changed effective or pending metadata")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now()
		WHERE grantee_member_id = $1 AND permission_keys @> '["auth.applications:manage"]'::jsonb`, ownerID); err != nil {
		t.Fatal(err)
	}
	if got := patchApplication(t, handler, appID, access.AccessToken, `{"name":"Outside owner envelope"}`); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("Agent public update bypassed its owner's authority: status=%d", got.Code)
	}
	if got := patchApplication(t, handler, appID, token, `{"name":"Outside publisher authority"}`); got.Code != http.StatusForbidden {
		t.Fatalf("human public update bypassed publisher authority: status=%d", got.Code)
	}
}

func TestPublicInstallationManifestApprovalHTTPRequiresHumanOrAgentDeltaCoverage(t *testing.T) {
	for _, principalType := range []string{"human", "agent"} {
		t.Run(principalType, func(t *testing.T) {
			ctx := context.Background()
			st, authz, apps, ownerID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
			installed, err := apps.InstallSpace(ctx, ownerID, appID, spaceID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE applications SET visibility = 'public', review_status = 'approved',
				manifest_permissions = '["auth.authz:check","auth.tokens:introspect"]'::jsonb,
				allowed_scopes = '["auth.authz:check","auth.tokens:introspect"]'::jsonb WHERE id = $1`, appID); err != nil {
				t.Fatal(err)
			}
			actorID, token := ownerID, manifestToken(t, sessions, ownerID)
			if principalType == "agent" {
				created, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "Customer administrator"})
				if err != nil {
					t.Fatal(err)
				}
				actorID = created.ID
				for _, key := range []string{"auth.applications:manage", "auth.grants:assign"} {
					seedTestInlineGrant(t, st, spaceID, ownerID, actorID, key)
				}
				if _, err := st.Pool.Exec(ctx, `INSERT INTO assign_rights (id, holder_member_id, permission_keys, anchor_space_id, covers_subtree, source)
					VALUES ('ar_public_manifest_agent', $2, '["auth.tokens:introspect"]'::jsonb, $1, true, 'system')`, spaceID, actorID); err != nil {
					t.Fatal(err)
				}
				access, err := sessions.CreateAgentAccess(ctx, actorID, spaceID, security.DefaultApplicationAudience)
				if err != nil {
					t.Fatal(err)
				}
				token = access.AccessToken
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1`, actorID); err != nil {
				t.Fatal(err)
			}
			if got := approveManifest(t, handler, spaceID, installed.ID, token); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
				t.Fatalf("uncovered public installation approval status=%d", got.Code)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = NULL WHERE holder_member_id = $1`, actorID); err != nil {
				t.Fatal(err)
			}
			if got := approveManifest(t, handler, spaceID, installed.ID, token); got.Code != http.StatusOK {
				t.Fatalf("covered public installation approval status=%d body=%s", got.Code, got.Body.String())
			}
			decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: installed.MemberID, Permission: "auth.tokens:introspect", ResourceSpace: spaceID})
			if err != nil || decision.Effect != engine.Allow {
				t.Fatalf("approved installation authority=%s error=%v", decision.Effect, err)
			}
		})
	}
}
