package principal

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/requestinfo"
	"github.com/plystra/auth/internal/security"
)

func TestManagedAPIKeyGrantsHTTPPreservesCredentialAndIndependentKeys(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
	if _, err := apps.InstallSpace(ctx, actorID, appID, spaceID); err != nil {
		t.Fatal(err)
	}
	input := application.CreateManagedKeyInput{Name: "grant-replacement", Grants: []string{"auth.authz:check", "auth.tokens:introspect"},
		RestrictTo: []application.KeyRestriction{{SpaceID: spaceID}}, AllowedIPCIDRs: []string{"192.0.2.0/24"},
		AllowSubjectAssertion: true, ExpiresAt: time.Now().Add(time.Hour)}
	original, raw, err := apps.CreateManagedKey(ctx, actorID, appID, input)
	if err != nil {
		t.Fatal(err)
	}
	_, rotated, err := apps.RotateManagedKey(ctx, actorID, appID, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, independent, err := apps.CreateManagedKey(ctx, actorID, appID, input)
	if err != nil {
		t.Fatal(err)
	}
	token := manifestToken(t, sessions, actorID)
	path := "/v1/applications/" + appID + "/api-keys/" + original.ID + "/grants"
	var versionBefore int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	response := requestApplicationKey(t, handler, http.MethodPut, path, token, []byte(`{"grants":["auth.tokens:introspect"]}`))
	var result struct {
		Data application.ManagedKey `json:"data"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil {
		t.Fatalf("grant replacement status=%d", response.Code)
	}
	original.Grants = []string{"auth.tokens:introspect"}
	if diff := cmp.Diff(original, result.Data); diff != "" {
		t.Fatalf("grant replacement changed unrelated metadata (-want +got):\n%s", diff)
	}
	for _, sensitive := range []string{raw.Value(), rotated.Value(), "secret_hash", `"secret"`} {
		if strings.Contains(response.Body.String(), sensitive) {
			t.Fatal("grant response exposed a credential")
		}
	}
	authCtx := requestinfo.With(ctx, requestinfo.Info{IP: net.ParseIP("192.0.2.9")})
	for _, secret := range []string{raw.Value(), rotated.Value()} {
		current, err := apps.AuthenticateKey(authCtx, secret)
		if err != nil || !slices.Equal(current.Scopes, original.Grants) {
			t.Fatal("current or grace secret did not use replaced grants")
		}
	}
	if current, err := apps.AuthenticateKey(authCtx, independent.Value()); err != nil || !slices.Equal(current.Scopes, input.Grants) {
		t.Fatal("grant replacement affected a different key")
	}
	empty := requestApplicationKey(t, handler, http.MethodPut, path, token, []byte(`{"grants":[]}`))
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), `"grants":[]`) {
		t.Fatalf("clearing all grants status=%d", empty.Code)
	}
	var versionAfter int64
	if err := st.Pool.QueryRow(ctx, `SELECT policy_version FROM spaces WHERE id = $1`, spaceID).Scan(&versionAfter); err != nil || versionAfter != versionBefore {
		t.Fatal("derived credential update changed Space authority")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'application.key.grants.replace'
		AND resource_id = $1 AND resource_type = 'api_key' AND application_id = $2 AND space_id = $3
		AND member_id = $4 AND user_id = 'usr_principal_actor' AND plane = 'principal'
		AND metadata ? 'previous_grants' AND metadata ? 'grants'`, original.ID, appID, spaceID, actorID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("grant replacement audit count=%d error=%v", count, err)
	}
	var serialized string
	if err := st.Pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a))::text FROM audit_logs a WHERE action = 'application.key.grants.replace'`).Scan(&serialized); err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{raw.Value(), rotated.Value(), independent.Value(), token, "ply_rt_", "ply_ag_", "ply_ops_"} {
		if strings.Contains(serialized, sensitive) {
			t.Fatal("grant audit exposed a credential")
		}
	}
}

func TestManagedAPIKeyGrantsHTTPRejectsInvalidAndUnavailableTargets(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
	key, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "validation", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	token := manifestToken(t, sessions, actorID)
	path := "/v1/applications/" + appID + "/api-keys/" + key.ID + "/grants"
	for _, body := range []string{`{}`, `{"grants":null}`, `{"grants":[""]}`, `{"grants":[" auth.authz:check"]}`,
		`{"grants":["auth.authz:check","auth.authz:check"]}`, `{"grants":[],"secret":"unexpected"}`} {
		got := requestApplicationKey(t, handler, http.MethodPut, path, token, []byte(body))
		if got.Code != http.StatusBadRequest {
			t.Fatalf("invalid grant body accepted: status=%d", got.Code)
		}
	}
	outside := requestApplicationKey(t, handler, http.MethodPut, path, token, []byte(`{"grants":["auth.audit:write"]}`))
	if outside.Code != http.StatusForbidden || !strings.Contains(outside.Body.String(), "GRANT_EXCEEDS_OWNER") {
		t.Fatalf("out-of-manifest grants status=%d", outside.Code)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.tokens:introspect'`); err != nil {
		t.Fatal(err)
	}
	disabled := requestApplicationKey(t, handler, http.MethodPut, path, token, []byte(`{"grants":["auth.tokens:introspect"]}`))
	if disabled.Code != http.StatusForbidden || !strings.Contains(disabled.Body.String(), "PERMISSION_DISABLED") {
		t.Fatalf("disabled key grant status=%d", disabled.Code)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO applications (id, space_id, name, client_id, manifest_permissions)
		VALUES ('app_wrong_grants', $1, 'Other', 'wrong-grants', '["auth.authz:check"]'::jsonb)`, spaceID); err != nil {
		t.Fatal(err)
	}
	wrongApp := requestApplicationKey(t, handler, http.MethodPut, "/v1/applications/app_wrong_grants/api-keys/"+key.ID+"/grants", token, []byte(`{"grants":[]}`))
	if wrongApp.Code != http.StatusNotFound {
		t.Fatalf("cross-application update status=%d", wrongApp.Code)
	}
	for _, state := range []string{"expired", "revoked", "application_suspended"} {
		t.Run(state, func(t *testing.T) {
			var query string
			switch state {
			case "expired":
				query = `UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE id = $1`
			case "revoked":
				query = `UPDATE api_keys SET revoked_at = now() WHERE id = $1`
			case "application_suspended":
				query = `UPDATE applications SET status = 'suspended' WHERE id = (SELECT application_id FROM api_keys WHERE id = $1)`
			}
			if _, err := st.Pool.Exec(ctx, query, key.ID); err != nil {
				t.Fatal(err)
			}
			got := requestApplicationKey(t, handler, http.MethodPut, path, token, []byte(`{"grants":[]}`))
			if got.Code != http.StatusConflict {
				t.Fatalf("inactive target update status=%d", got.Code)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() + interval '1 hour', revoked_at = NULL WHERE id = $1`, key.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE applications SET status = 'active' WHERE id = $1`, appID); err != nil {
				t.Fatal(err)
			}
		})
	}
	var grants string
	if err := st.Pool.QueryRow(ctx, `SELECT scopes::text FROM api_keys WHERE id = $1`, key.ID).Scan(&grants); err != nil || grants != `["auth.authz:check"]` {
		t.Fatal("rejected update changed stored grants")
	}
}

func TestManagedAPIKeyGrantReplacementSerializesWithManifestAndRevocation(t *testing.T) {
	for _, operation := range []string{"manifest", "revocation"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			_, _, apps, actorID, _, _, _, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
			key, raw, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
				Name: "concurrent-grants", Grants: []string{"auth.authz:check", "auth.tokens:introspect"}, ExpiresAt: time.Now().Add(time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			updateResult, otherResult := make(chan error, 1), make(chan error, 1)
			go func() {
				<-start
				_, err := apps.UpdateManagedKeyGrants(ctx, actorID, appID, key.ID, []string{"auth.authz:check", "auth.tokens:introspect"})
				updateResult <- err
			}()
			go func() {
				<-start
				if operation == "manifest" {
					manifest := []string{"auth.authz:check"}
					_, err := apps.Update(ctx, actorID, appID, application.UpdateInput{ManifestPermissions: &manifest})
					otherResult <- err
				} else {
					_, err := apps.RevokeManagedKey(ctx, actorID, appID, key.ID)
					otherResult <- err
				}
			}()
			close(start)
			if err := <-otherResult; err != nil {
				t.Fatal(err)
			}
			if err := <-updateResult; err != nil {
				code := "GRANT_EXCEEDS_OWNER"
				if operation == "revocation" {
					code = "CONFLICT"
				}
				assertPrincipalError(t, err, code)
			}
			current, err := apps.AuthenticateKey(ctx, raw.Value())
			if operation == "revocation" {
				if err == nil {
					t.Fatal("concurrent grants restored a revoked key")
				}
			} else if err != nil || !slices.Equal(current.Scopes, []string{"auth.authz:check"}) {
				t.Fatal("concurrent replacement escaped manifest narrowing")
			}
		})
	}
}

func TestAgentKeyGrantManagementRequiresCurrentOwnerAuthority(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
	key, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "agent-manager", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{OwnerMemberID: actorID, Name: "Key manager"})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, actorID, created.ID, "auth.applications:manage")
	access, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/applications/" + appID + "/api-keys/" + key.ID + "/grants"
	allowed := requestApplicationKey(t, handler, http.MethodPut, path, access.AccessToken, []byte(`{"grants":["auth.tokens:introspect"]}`))
	if allowed.Code != http.StatusOK {
		t.Fatalf("authorized Agent grant management status=%d", allowed.Code)
	}
	var owners string
	if err := st.Pool.QueryRow(ctx, `SELECT owner_chain::text FROM audit_logs WHERE action = 'application.key.grants.replace'
		AND member_id = $1 AND application_id = $2`, created.ID, appID).Scan(&owners); err != nil || !strings.Contains(owners, actorID) {
		t.Fatal("Agent key management audit omitted its owner")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now()
		WHERE grantee_member_id = $1 AND permission_keys ? 'auth.applications:manage'`, actorID); err != nil {
		t.Fatal(err)
	}
	denied := requestApplicationKey(t, handler, http.MethodPut, path, access.AccessToken, []byte(`{"grants":[]}`))
	if denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "OWNER_ENVELOPE_EXCLUDED") {
		t.Fatalf("Agent bypassed owner authority: status=%d", denied.Code)
	}
}

func TestManagedAPIKeyGrantsHTTPRollsBackOnAuditFailure(t *testing.T) {
	ctx := context.Background()
	st, _, apps, actorID, _, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check", "auth.tokens:introspect"})
	key, raw, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
		Name: "rollback", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_key_grant_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'application.key.grants.replace' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_key_grant_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_key_grant_audit()`); err != nil {
		t.Fatal(err)
	}
	token := manifestToken(t, sessions, actorID)
	path := "/v1/applications/" + appID + "/api-keys/" + key.ID + "/grants"
	body := []byte(`{"grants":["auth.tokens:introspect"]}`)
	failed := requestApplicationKey(t, handler, http.MethodPut, path, token, body)
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("update survived audit failure: status=%d", failed.Code)
	}
	current, err := apps.AuthenticateKey(ctx, raw.Value())
	if err != nil || !slices.Equal(current.Scopes, key.Grants) {
		t.Fatal("failed audit changed grants or credential")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'application.key.grants.replace'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed update left a success audit")
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_key_grant_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if retried := requestApplicationKey(t, handler, http.MethodPut, path, token, body); retried.Code != http.StatusOK {
		t.Fatalf("retry after audit recovery status=%d", retried.Code)
	}
}

func TestManagedAPIKeyGrantsHTTPUsesUnifiedManagementDecision(t *testing.T) {
	for _, condition := range []string{"group_scope", "envelope", "disabled", "principal_kind"} {
		t.Run(condition, func(t *testing.T) {
			ctx := context.Background()
			st, authz, apps, actorID, spaceID, sessions, handler, appID := installationFixture(t, []string{"auth.authz:check"})
			key, _, err := apps.CreateManagedKey(ctx, actorID, appID, application.CreateManagedKeyInput{
				Name: "governance", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
			})
			if err != nil {
				t.Fatal(err)
			}
			token := manifestToken(t, sessions, actorID)
			var query string
			var args []any
			switch condition {
			case "group_scope":
				if _, err := st.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name) VALUES ('grp_key_manager', $1, 'Key manager')`, spaceID); err != nil {
					t.Fatal(err)
				}
				query = `UPDATE authorization_grants SET scope = 'group', anchor_group_id = 'grp_key_manager'
					WHERE grantee_member_id = $1 AND permission_keys ? 'auth.applications:manage'`
				args = []any{actorID}
			case "envelope":
				if _, err := st.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, spaceID); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				query = `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.applications:manage'`
			case "principal_kind":
				query = `UPDATE permissions SET principal_kinds = '["agent"]'::jsonb WHERE key = 'auth.applications:manage'`
			}
			if query != "" {
				if _, err := st.Pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			decision, _, err := authz.Check(ctx, authorization.CheckRequest{MemberID: actorID, Permission: "auth.applications:manage", ResourceSpace: spaceID})
			if err != nil || decision.Effect != engine.Deny {
				t.Fatalf("governance check did not deny condition=%s error=%v", condition, err)
			}
			path := "/v1/applications/" + appID + "/api-keys/" + key.ID + "/grants"
			response := requestApplicationKey(t, handler, http.MethodPut, path, token, []byte(`{"grants":[]}`))
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), decision.Code) {
				t.Fatalf("management differs from engine: condition=%s status=%d expected=%s", condition, response.Code, decision.Code)
			}
			var scopes string
			if err := st.Pool.QueryRow(ctx, `SELECT scopes::text FROM api_keys WHERE id = $1`, key.ID).Scan(&scopes); err != nil || scopes != `["auth.authz:check"]` {
				t.Fatal("denied management mutated key grants")
			}
		})
	}
}
