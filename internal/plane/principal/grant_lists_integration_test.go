package principal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func grantListHTTP(ctx context.Context, f groupRemovalFixture, token, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+f.spaceID+"/grants"+query, nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	return out
}

func decodeGrantPage(t *testing.T, response *httptest.ResponseRecorder) grantListOutput {
	t.Helper()
	var page grantListOutput
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page.Body) != nil || page.Body.Data == nil {
		t.Fatalf("grant list response: status=%d body=%s", response.Code, response.Body.String())
	}
	return page
}

func seedGrantList(t *testing.T, f groupRemovalFixture) {
	t.Helper()
	if _, err := f.store.Pool.Exec(context.Background(), `
		UPDATE authorization_grants SET revoked_at = now() WHERE id IN ('grt_remove_a', 'grt_remove_b');
		DELETE FROM group_members WHERE member_id = $1 AND group_id = 'grp_remove_b';
		INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_list_child', $2, 'Child', 'grp_remove_a');
		INSERT INTO members (id, space_id, name, type) VALUES
		    ('mem_list_outside', $2, 'Outside', 'human'), ('mem_list_unplaced', $2, 'Unplaced', 'human'),
		    ('mem_list_multiple', $2, 'Multiple', 'human');
		INSERT INTO group_members (group_id, member_id, space_id, source) VALUES
		    ('grp_remove_b', 'mem_list_outside', $2, 'manual'), ('grp_remove_a', 'mem_list_multiple', $2, 'manual'),
		    ('grp_remove_b', 'mem_list_multiple', $2, 'manual');
		INSERT INTO roles (id, space_id, name) VALUES ('rol_list', $2, 'Configured role');
		INSERT INTO role_permissions (role_id, permission_id) SELECT 'rol_list', id FROM permissions WHERE key = 'auth.members:manage';
		INSERT INTO authorization_grants (id, space_id, role_id, permission_keys, grantee_member_id, grantee_group_id,
		    scope, anchor_group_id, granted_by, created_at, revoked_at) VALUES
		    ('grt_list_a', $2, NULL, '["auth.members:manage"]', NULL, 'grp_remove_a', 'group_tree', 'grp_remove_a', $3, '2025-01-01', NULL),
		    ('grt_list_b', $2, 'rol_list', NULL, NULL, 'grp_list_child', 'group_tree', 'grp_remove_b', $3, '2025-01-01', NULL),
		    ('grt_list_c', $2, NULL, '["auth.members:manage"]', $1, NULL, 'group_tree', 'grp_remove_b', $3, '2025-01-01', NULL),
		    ('grt_list_d', $2, NULL, '["auth.members:manage"]', 'mem_list_outside', NULL, 'group_tree', 'grp_remove_a', $3, '2025-01-01', NULL),
		    ('grt_list_e', $2, NULL, '["auth.members:manage"]', 'mem_list_unplaced', NULL, 'group_tree', 'grp_remove_a', $3, '2025-01-01', NULL),
		    ('grt_list_f', $2, NULL, '["auth.members:manage"]', 'mem_list_multiple', NULL, 'group_tree', 'grp_remove_a', $3, '2025-01-01', NULL),
		    ('grt_list_g', $2, NULL, '["auth.members:manage"]', NULL, 'grp_remove_b', 'group_tree', 'grp_remove_a', $3, '2025-01-01', NULL),
		    ('grt_list_h', $2, NULL, '["auth.members:manage"]', NULL, 'grp_list_child', 'group_tree', 'grp_remove_a', $3, '2025-01-01', now());
		UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:manage'`,
		pgx.QueryExecModeSimpleProtocol, f.target.ID, f.spaceID, f.owner.ID); err != nil {
		t.Fatal(err)
	}
}

func restrictGrantListManager(t *testing.T, f groupRemovalFixture, actorID, groupID string) {
	t.Helper()
	if _, err := f.store.Pool.Exec(context.Background(), `
		UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1;
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_group_id, granted_by)
		VALUES ('grt_list_manager_' || $1, $2, '["auth.grants:assign"]', $1, 'group_tree', $3, $4)`,
		pgx.QueryExecModeSimpleProtocol, actorID, f.spaceID, groupID, f.owner.ID); err != nil {
		t.Fatal(err)
	}
}

func TestGrantListHTTPFiltersRecipientPositionBeforePagination(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	seedGrantList(t, f)
	all := decodeGrantPage(t, grantListHTTP(ctx, f, f.token, ""))
	for _, id := range []string{"grt_list_a", "grt_list_b", "grt_list_c", "grt_list_d", "grt_list_e", "grt_list_f", "grt_list_g"} {
		if !slices.ContainsFunc(all.Body.Data, func(g authorization.Grant) bool { return g.ID == id }) {
			t.Fatalf("Space authority could not inspect configured grant %s", id)
		}
	}
	created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "grant-reader"})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := f.sessions.CreateAgentAccess(ctx, created.ID, f.spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	restrictGrantListManager(t, f, created.ID, "grp_remove_a")
	restrictGrantListManager(t, f, f.owner.ID, "grp_remove_a")
	var seen []string
	cursor := ""
	for range 4 {
		page := decodeGrantPage(t, grantListHTTP(ctx, f, f.token, "?limit=1&cursor="+url.QueryEscape(cursor)))
		if len(page.Body.Data) != 1 {
			t.Fatalf("filtering left an incomplete page: %+v", page.Body.Data)
		}
		seen = append(seen, page.Body.Data[0].ID)
		if page.Body.NextCursor == "" {
			break
		}
		if cursor == "" {
			// Newer grants must not move the cursor or repeat already read rows.
			if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
				(id, space_id, permission_keys, grantee_group_id, scope, anchor_group_id, granted_by)
				VALUES ('grt_list_new', $1, '["auth.members:manage"]', 'grp_remove_a', 'group', 'grp_remove_a', $2)`, f.spaceID, f.owner.ID); err != nil {
				t.Fatal(err)
			}
		}
		cursor = page.Body.NextCursor
	}
	if !slices.Equal(seen, []string{"grt_list_c", "grt_list_b", "grt_list_a"}) {
		t.Fatalf("recipient-filtered tied timestamp pages = %v", seen)
	}
	human := decodeGrantPage(t, grantListHTTP(ctx, f, f.token, ""))
	agentPage := decodeGrantPage(t, grantListHTTP(ctx, f, tokens.AccessToken, ""))
	if len(human.Body.Data) != 4 || !slices.EqualFunc(human.Body.Data, agentPage.Body.Data, func(a, b authorization.Grant) bool { return a.ID == b.ID }) {
		t.Fatal("equivalent human and Agent authority returned different grant lists")
	}
	for _, grant := range human.Body.Data {
		if grant.ID == "grt_list_b" && (grant.RoleID != "rol_list" || len(grant.Permissions) != 0 || grant.AnchorGroupID != "grp_remove_b") {
			t.Fatalf("role configuration was lost: %+v", grant)
		}
		if grant.ID == "grt_list_c" && (!slices.Equal(grant.Permissions, []string{"auth.members:manage"}) || grant.GranteeMemberID != f.target.ID) {
			t.Fatalf("disabled business grant configuration was lost: %+v", grant)
		}
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'active' WHERE key = 'auth.members:manage';
		INSERT INTO group_envelopes (group_id) VALUES ('grp_remove_a');
		INSERT INTO group_envelope_entries (group_id, permission_id, mode)
		SELECT 'grp_remove_a', id, 'delegate' FROM permissions WHERE key = 'auth.grants:assign'`); err != nil {
		t.Fatal(err)
	}
	dormant := decodeGrantPage(t, grantListHTTP(ctx, f, f.token, ""))
	if !slices.EqualFunc(human.Body.Data, dormant.Body.Data, func(a, b authorization.Grant) bool { return a.ID == b.ID }) {
		t.Fatal("envelope-excluded business configuration disappeared from the governance list")
	}
}

func TestGrantListHTTPCursorsRequireCurrentAuthority(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	seedGrantList(t, f)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_list_other', 'Other', 'list-other');
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_list_other', 'spc_list_other', '["auth.grants:assign"]', $1, 'space', 'spc_list_other', $1)`, pgx.QueryExecModeSimpleProtocol, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	restrictGrantListManager(t, f, f.owner.ID, "grp_remove_a")
	first := decodeGrantPage(t, grantListHTTP(ctx, f, f.token, "?limit=1"))
	if first.Body.NextCursor == "" {
		t.Fatal("fixture did not produce a next page")
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?cursor=invalid!", "?cursor=" + strings.Repeat("a", 513)} {
		if response := grantListHTTP(ctx, f, f.token, query); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid query status=%d", response.Code)
		}
	}
	for _, id := range []string{"grt_missing", "grt_list_other", "grt_list_d", "grt_list_e", "grt_list_f", "usr_wrong", "grt_nul\x00"} {
		response := grantListHTTP(ctx, f, f.token, "?cursor="+base64.RawURLEncoding.EncodeToString([]byte(id)))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "VALIDATION_FAILED") {
			t.Fatalf("invalid or unauthorized cursor accepted: status=%d", response.Code)
		}
	}
	if response := grantRevocationHTTP(ctx, f, f.token, first.Body.Data[0].ID); response.Code != http.StatusOK {
		t.Fatalf("revoke listed grant status=%d body=%s", response.Code, response.Body.String())
	}
	remaining := decodeGrantPage(t, grantListHTTP(ctx, f, f.token, "?cursor="+url.QueryEscape(first.Body.NextCursor)))
	if len(remaining.Body.Data) != 2 || remaining.Body.Data[0].ID != "grt_list_b" || remaining.Body.Data[1].ID != "grt_list_a" {
		t.Fatal("revoked cursor could not continue the visible traversal")
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_list_manager_' || $1`, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	if response := grantListHTTP(ctx, f, f.token, "?cursor="+url.QueryEscape(first.Body.NextCursor)); response.Code != http.StatusForbidden {
		t.Fatalf("cursor retained revoked authority: status=%d", response.Code)
	}
}

func TestGrantListHTTPRechecksOwnerCatalogEnvelopeAndTokenScope(t *testing.T) {
	for _, scenario := range []string{"disabled", "deprecated", "principal_kind", "envelope", "owner_excluded", "owner_inactive", "ancestor_inactive", "token_scope"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			f := newGroupRemovalFixture(t)
			ownerID := f.owner.ID
			expiresAt := time.Now().Add(time.Hour)
			if scenario == "ancestor_inactive" {
				parent, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "reader-parent", ExpiresAt: expiresAt})
				if err != nil {
					t.Fatal(err)
				}
				seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, parent.ID, "auth.grants:assign")
				ownerID, expiresAt = parent.ID, parent.ExpiresAt
			}
			created, _, err := (&agent.Service{Store: f.store}).Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "reader", ExpiresAt: expiresAt})
			if err != nil {
				t.Fatal(err)
			}
			seedTestInlineGrant(t, f.store, f.spaceID, f.owner.ID, created.ID, "auth.grants:assign")
			issued, err := f.sessions.CreateAgentAccess(ctx, created.ID, f.spaceID, security.DefaultApplicationAudience)
			if err != nil {
				t.Fatal(err)
			}
			first := decodeGrantPage(t, grantListHTTP(ctx, f, issued.AccessToken, "?limit=1"))
			wantCode := ""
			var scopes []string
			switch scenario {
			case "disabled", "deprecated":
				_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET status = $1 WHERE key = 'auth.grants:assign'`, scenario)
				wantCode = "PERMISSION_DISABLED"
			case "principal_kind":
				_, err = f.store.Pool.Exec(ctx, `UPDATE permissions SET principal_kinds = '["human"]' WHERE key = 'auth.grants:assign'`)
				wantCode = "PRINCIPAL_KIND_NOT_ALLOWED"
			case "envelope":
				_, err = f.store.Pool.Exec(ctx, `INSERT INTO space_envelopes (space_id) VALUES ($1)`, f.spaceID)
				wantCode = "ENVELOPE_EXCLUDED"
			case "owner_excluded":
				_, err = f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id = $1`, f.owner.ID)
				wantCode = "OWNER_ENVELOPE_EXCLUDED"
			case "owner_inactive", "ancestor_inactive":
				_, err = f.store.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, f.owner.ID)
				wantCode = "OWNER_INACTIVE"
			case "token_scope":
				scopes = []string{"self:read"}
				issued, err = f.sessions.CreateAgentDelegatedAccess(ctx, created.ID, f.spaceID, security.DefaultApplicationAudience, f.owner.ID, scopes, 0)
				wantCode = "TOKEN_SCOPE_EXCLUDED"
			}
			if err != nil {
				t.Fatal(err)
			}
			decision, _, err := f.authz.Check(ctx, authorization.CheckRequest{MemberID: created.ID, Permission: "auth.grants:assign", ResourceSpace: f.spaceID, TokenScopes: scopes})
			if err != nil {
				t.Fatal(err)
			}
			response := grantListHTTP(ctx, f, issued.AccessToken, "?cursor="+url.QueryEscape(first.Body.NextCursor))
			if scenario == "deprecated" {
				if decision.Effect != engine.Allow || response.Code != http.StatusOK {
					t.Fatalf("existing deprecated authority stopped working: engine=%s status=%d", decision.Code, response.Code)
				}
				return
			}
			if decision.Effect != engine.Deny || decision.Code != wantCode || response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"`+wantCode+`"`) {
				t.Fatalf("grant listing diverged from check: engine=%s want=%s status=%d body=%s", decision.Code, wantCode, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), `"data"`) {
				t.Fatal("denied listing returned partial grants")
			}
		})
	}
}

func TestGrantListHTTPUsesSameActiveRecipientGroupsAsManagement(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	seedGrantList(t, f)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id, space_id, source)
		VALUES ('grp_remove_b', $1, $2, 'manual'); UPDATE groups SET status = 'suspended' WHERE id = 'grp_remove_b'`,
		pgx.QueryExecModeSimpleProtocol, f.target.ID, f.spaceID); err != nil {
		t.Fatal(err)
	}
	restrictGrantListManager(t, f, f.owner.ID, "grp_remove_a")
	page := decodeGrantPage(t, grantListHTTP(ctx, f, f.token, ""))
	if !slices.ContainsFunc(page.Body.Data, func(g authorization.Grant) bool { return g.ID == "grt_list_c" }) {
		t.Fatal("suspended membership changed the listing's active management position")
	}
	if response := grantRevocationHTTP(ctx, f, f.token, "grt_list_c"); response.Code != http.StatusOK {
		t.Fatalf("listed grant and revocation used different positions: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGrantListHTTPReturnsEmptyArrayForAuthorizedEmptyGroup(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO groups (id, space_id, name, parent_id) VALUES ('grp_list_empty', $1, 'Empty', 'grp_remove_root')`, f.spaceID); err != nil {
		t.Fatal(err)
	}
	restrictGrantListManager(t, f, f.owner.ID, "grp_list_empty")
	response := grantListHTTP(ctx, f, f.token, "")
	page := decodeGrantPage(t, response)
	if len(page.Body.Data) != 0 || page.Body.NextCursor != "" || strings.Contains(response.Body.String(), "next_cursor") {
		t.Fatalf("empty group pagination: %s", response.Body.String())
	}
}

func TestGrantListHTTPFailsClosedWhenStorageIsUnavailable(t *testing.T) {
	ctx := context.Background()
	f := newGroupRemovalFixture(t)
	pool, err := pgxpool.NewWithConfig(ctx, f.store.Pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	mux := http.NewServeMux()
	(&API{Authorization: &authorization.Service{Store: &store.Store{Pool: pool}}, Sessions: f.sessions}).Register(humago.New(mux, route.HumaConfig("unavailable grants", "1.0.0")))
	f.handler = route.Middleware(route.Principal, mux)
	response := grantListHTTP(ctx, f, f.token, "")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "UNAVAILABLE") || strings.Contains(response.Body.String(), `"data"`) {
		t.Fatalf("storage failure response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGrantListHTTPResolvesPositionsAfterConcurrentMembershipChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newGroupRemovalFixture(t)
	seedGrantList(t, f)
	restrictGrantListManager(t, f, f.owner.ID, "grp_remove_a")
	locked, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- f.store.InTx(ctx, func(q *db.Queries) error {
			if _, err := q.LockMemberForAuthorization(ctx, db.LockMemberForAuthorizationParams{ID: f.target.ID}); err != nil {
				return err
			}
			if _, err := q.LockSpaceForAuthorization(ctx, db.LockSpaceForAuthorizationParams{ID: f.spaceID}); err != nil {
				return err
			}
			close(locked)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := q.RemoveGroupMember(ctx, db.RemoveGroupMemberParams{GroupID: "grp_remove_a", MemberID: f.target.ID, SpaceID: f.spaceID}); err != nil {
				return err
			}
			return q.AddGroupMember(ctx, db.AddGroupMemberParams{GroupID: "grp_remove_b", MemberID: f.target.ID, SpaceID: f.spaceID, Source: "manual"})
		})
	}()
	select {
	case <-locked:
	case err := <-writer:
		t.Fatalf("could not establish membership barrier: %v", err)
	}
	listing := make(chan *httptest.ResponseRecorder, 1)
	go func() { listing <- grantListHTTP(ctx, f, f.token, "") }()
	for {
		var waiting bool
		if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
			AND wait_event_type = 'Lock' AND query LIKE '%spaces%FOR UPDATE%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case response := <-listing:
			t.Fatalf("listing bypassed the governing Space lock: status=%d", response.Code)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	page := decodeGrantPage(t, <-listing)
	if len(page.Body.Data) != 2 || slices.ContainsFunc(page.Body.Data, func(g authorization.Grant) bool { return g.ID == "grt_list_c" }) {
		t.Fatal("grant list leaked a recipient moved outside current authority")
	}
}

func TestGrantListRouteDeclaresHumanAgentAndAuthoritativeCheck(t *testing.T) {
	api := humago.New(http.NewServeMux(), route.HumaConfig("grant list contract", "1.0.0"))
	(&API{}).Register(api)
	for _, spec := range route.Specs() {
		if spec.Name == "grants.list" {
			if spec.Method != http.MethodGet || spec.Path != "/v1/spaces/{id}/grants" || spec.Permission != "auth.grants:assign" || !spec.AuthoritativeCheck || len(spec.Subjects) != 1 || spec.Subjects[0] != route.HumanAgent {
				t.Fatalf("grant list route = %+v", spec)
			}
			operation := api.OpenAPI().Paths[spec.Path].Get
			if operation == nil || operation.Responses["200"] == nil || len(operation.Parameters) != 4 {
				t.Fatal("OpenAPI omitted grant pagination or response")
			}
			return
		}
	}
	t.Fatal("grant list route was not registered")
}
