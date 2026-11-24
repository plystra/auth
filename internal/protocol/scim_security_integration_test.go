package protocol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/credential"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

type scimFixture struct {
	store     *store.Store
	service   *enterprise.Service
	directory enterprise.Directory
	owner     authorization.Member
	ctx       context.Context
	handler   http.Handler
}

func newSCIMFixture(t *testing.T) scimFixture {
	t.Helper()
	ctx := context.Background()
	database, err := protocolDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id,email,email_normalized,password_hash,status)
		VALUES ('usr_scim_admin','admin@scim.test','admin@scim.test','test-hash','active')`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	_, owner, err := authz.CreateSpace(ctx, "usr_scim_admin", "Directory security", "directory-security")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_scim_connection',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, owner.SpaceID, owner.ID); err != nil {
		t.Fatal(err)
	}
	svc := &enterprise.Service{Store: st, Authorization: authz, Passwords: security.DefaultPasswordHasher()}
	ctx = authorization.WithHumanActor(ctx, owner.ID, "usr_scim_admin")
	directory, err := svc.CreateDirectory(ctx, owner.ID, owner.SpaceID, enterprise.DirectoryInput{Name: "Workforce"})
	if err != nil {
		t.Fatal(err)
	}
	var mux http.ServeMux
	(HTTP{Enterprise: svc}).Register(&mux)
	return scimFixture{store: st, service: svc, directory: directory, owner: owner, ctx: ctx, handler: &mux}
}

type scimTestResource struct {
	ID          string            `json:"id"`
	UserName    string            `json:"userName"`
	DisplayName string            `json:"displayName"`
	Name        map[string]string `json:"name"`
	Active      bool              `json:"active"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
	Meta struct {
		Version  string `json:"version"`
		Location string `json:"location"`
	} `json:"meta"`
}

func (f scimFixture) request(t *testing.T, method, path, body, version string, status int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/scim/v2/"+f.directory.ID+"/"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.directory.Token.Value())
	req.Header.Set("Content-Type", "application/scim+json")
	if version != "" {
		req.Header.Set("If-Match", version)
	}
	res := httptest.NewRecorder()
	f.handler.ServeHTTP(res, req)
	if res.Code != status {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, res.Code, status, res.Body.String())
	}
	if status != http.StatusNoContent && res.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatalf("SCIM Content-Type = %q", res.Header().Get("Content-Type"))
	}
	return res
}

func scimResource(t *testing.T, res *httptest.ResponseRecorder) scimTestResource {
	t.Helper()
	var out scimTestResource
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID == "" || res.Header().Get("ETag") != out.Meta.Version || res.Header().Get("Location") != out.Meta.Location || out.Meta.Location == "" {
		t.Fatalf("resource metadata or concurrency headers missing: %+v", out)
	}
	return out
}

func (f scimFixture) user(t *testing.T, externalID string, active bool) scimTestResource {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"externalId": externalID, "userName": externalID + "@scim.test", "displayName": externalID, "active": active})
	return scimResource(t, f.request(t, "POST", "Users", string(body), "", 201))
}

func scimPatch(operations ...map[string]any) string {
	body, _ := json.Marshal(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": operations})
	return string(body)
}

func TestSCIMFullResourceRoundTripKeepsServerOwnedIdentityAndVersion(t *testing.T) {
	f := newSCIMFixture(t)
	f.handler = route.Middleware(route.Principal, f.handler)
	encode := func(fields map[string]any) string {
		t.Helper()
		body, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	for _, item := range []struct {
		collection string
		fields     map[string]any
	}{
		{"Users", map[string]any{"externalId": "person", "userName": "person@scim.test", "displayName": "Original", "active": true}},
		{"Groups", map[string]any{"externalId": "team", "displayName": "Original group", "members": []map[string]string{{"value": f.user(t, "member", true).ID, "type": "User"}}}},
	} {
		t.Run(item.collection, func(t *testing.T) {
			item.fields["id"] = "client-supplied-id"
			item.fields["meta"] = map[string]any{"location": "/client-chosen", "version": `W/"99"`}
			created := scimResource(t, f.request(t, http.MethodPost, item.collection, encode(item.fields), "", http.StatusCreated))
			path := item.collection + "/" + created.ID
			if created.ID == "client-supplied-id" || !strings.HasSuffix(created.Meta.Location, "/"+path) {
				t.Fatal("creation accepted client-owned identity metadata")
			}
			retrieved := f.request(t, http.MethodGet, path, "", "", http.StatusOK)
			var replacement map[string]any
			if err := json.Unmarshal(retrieved.Body.Bytes(), &replacement); err != nil {
				t.Fatal(err)
			}
			replacement["displayName"] = "Updated"
			f.request(t, http.MethodPut, path, encode(replacement), "", http.StatusPreconditionFailed)
			updated := scimResource(t, f.request(t, http.MethodPut, path, encode(replacement), created.Meta.Version, http.StatusOK))
			if updated.ID != created.ID || updated.Meta.Location != created.Meta.Location ||
				updated.Meta.Version == created.Meta.Version || updated.DisplayName != "Updated" ||
				!slices.Equal(updated.Members, created.Members) {
				t.Fatal("resource round trip lost identity, version, or members")
			}
			replacement["id"] = "another-resource"
			replacement["meta"] = map[string]any{"location": "/wrong", "version": updated.Meta.Version}
			replacement["displayName"] = "Updated again"
			f.request(t, http.MethodPut, path, encode(replacement), created.Meta.Version, http.StatusPreconditionFailed)
			current := scimResource(t, f.request(t, http.MethodPut, path, encode(replacement), updated.Meta.Version, http.StatusOK))
			if current.ID != created.ID || current.Meta.Location != created.Meta.Location || current.DisplayName != "Updated again" {
				t.Fatal("read-only metadata overrode the addressed resource")
			}
			if item.collection == "Groups" {
				replacement["members"] = []map[string]string{{"value": created.Members[0].Value, "type": "Group"}}
				f.request(t, http.MethodPut, path, encode(replacement), current.Meta.Version, http.StatusBadRequest)
				delete(replacement, "members")
			}
			replacement["unknown"] = true
			f.request(t, http.MethodPut, path, encode(replacement), current.Meta.Version, http.StatusBadRequest)
			if got := f.request(t, http.MethodGet, path, "", "", http.StatusOK).Header().Get("ETag"); got != current.Meta.Version {
				t.Fatal("rejected replacement changed the version")
			}
		})
	}
}

func TestSCIMDiscoveryDescribesSupportedResourcesAndRequiresCurrentDirectoryToken(t *testing.T) {
	f := newSCIMFixture(t)
	const issuer = "https://identity.example.test"
	mux := route.NewMux()
	(HTTP{Issuer: issuer, Enterprise: f.service}).Register(mux)
	f.handler = route.MiddlewareWithIdempotency(route.Principal, mux, f.store, (credential.Validator{Directory: f.service}).Validate)
	base := issuer + "/scim/v2/" + f.directory.ID

	config := f.request(t, http.MethodGet, "ServiceProviderConfig", "", "", http.StatusOK)
	var features struct {
		Schemas        []string
		Patch          struct{ Supported bool }
		ETag           struct{ Supported bool }
		Sort           struct{ Supported bool }
		Bulk           struct{ Supported bool }
		ChangePassword struct{ Supported bool }
		Filter         struct {
			Supported  bool
			MaxResults int32
		}
		AuthenticationSchemes []struct{ Type string }
	}
	if err := json.Unmarshal(config.Body.Bytes(), &features); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(features.Schemas, []string{scimConfig}) || !features.Patch.Supported || !features.ETag.Supported ||
		!features.Filter.Supported || features.Filter.MaxResults != enterprise.MaxSCIMPageSize ||
		features.Sort.Supported || features.Bulk.Supported || features.ChangePassword.Supported ||
		len(features.AuthenticationSchemes) != 1 || features.AuthenticationSchemes[0].Type != "oauthbearertoken" ||
		config.Header().Get("Location") != base+"/ServiceProviderConfig" {
		t.Fatal("service capabilities did not match the mounted directory")
	}

	for _, tc := range []struct {
		collection, first, second, schema string
	}{
		{"ResourceTypes", "User", "Group", scimCore + "ResourceType"},
		{"Schemas", scimUser, scimGroup, scimCore + "Schema"},
	} {
		t.Run(tc.collection, func(t *testing.T) {
			list := f.request(t, http.MethodGet, tc.collection+"?startIndex=999&count=0", "", "", http.StatusOK)
			var result struct {
				Schemas                                []string
				TotalResults, ItemsPerPage, StartIndex int
				Resources                              []struct {
					ID, Endpoint, Schema string
					Schemas              []string
					Attributes           []struct{ Name string }
					Meta                 struct{ Location string }
				}
			}
			if err := json.Unmarshal(list.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(result.Schemas, []string{scimListSchema}) || result.TotalResults != 2 ||
				result.ItemsPerPage != 2 || result.StartIndex != 1 || len(result.Resources) != 2 ||
				result.Resources[0].ID != tc.first || result.Resources[1].ID != tc.second {
				t.Fatal("discovery did not return the complete User and Group list")
			}
			for _, resource := range result.Resources {
				path := tc.collection + "/" + url.PathEscape(resource.ID)
				item := f.request(t, http.MethodGet, path, "", "", http.StatusOK)
				var got struct{ ID string }
				if json.Unmarshal(item.Body.Bytes(), &got) != nil || got.ID != resource.ID ||
					item.Header().Get("Location") != resource.Meta.Location ||
					resource.Meta.Location != base+"/"+path || !slices.Equal(resource.Schemas, []string{tc.schema}) {
					t.Fatal("discovery item did not resolve from its advertised location")
				}
			}
			f.request(t, http.MethodGet, tc.collection+"/Unknown", "", "", http.StatusNotFound)
			f.request(t, http.MethodGet, tc.collection+"?filter=", "", "", http.StatusForbidden)
			if tc.collection == "ResourceTypes" {
				if result.Resources[0].Endpoint != "/Users" || result.Resources[1].Endpoint != "/Groups" ||
					result.Resources[0].Schema != scimUser || result.Resources[1].Schema != scimGroup {
					t.Fatal("resource types did not reference the supported endpoints and schemas")
				}
			} else if !slices.ContainsFunc(result.Resources[0].Attributes, func(a struct{ Name string }) bool { return a.Name == "userName" }) ||
				!slices.ContainsFunc(result.Resources[1].Attributes, func(a struct{ Name string }) bool { return a.Name == "members" }) {
				t.Fatal("schema discovery did not describe provisionable fields")
			}
		})
	}
	old := f.directory
	other, err := f.service.CreateDirectory(f.ctx, f.owner.ID, f.owner.SpaceID, enterprise.DirectoryInput{Name: "Other workforce"})
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", other.Token.Value()} {
		f.directory.Token = secret.New(token)
		f.request(t, http.MethodGet, "ServiceProviderConfig", "", "", http.StatusUnauthorized)
	}
	f.directory, err = f.service.RotateDirectoryToken(f.ctx, f.owner.ID, f.owner.SpaceID, old.ID, old.Version)
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, http.MethodGet, "ResourceTypes", "", "", http.StatusOK)
	f.directory = old
	f.request(t, http.MethodGet, "Schemas", "", "", http.StatusUnauthorized)
}

func TestSCIMListPaginationNormalizesPageAndReturnsTotals(t *testing.T) {
	f := newSCIMFixture(t)
	f.user(t, "alice", true)
	f.user(t, "bob", true)
	f.request(t, http.MethodPost, "Groups", `{"externalId":"team","displayName":"Team"}`, "", http.StatusCreated)
	for _, tc := range []struct {
		name, path  string
		total, rows int
	}{
		{name: "users count only", path: "Users?count=0", total: 2},
		{name: "filtered count only", path: "Users?count=0&filter=" + url.QueryEscape(`userName eq "bob@scim.test"`), total: 1},
		{name: "groups count only", path: "Groups?count=0", total: 1},
		{name: "negative count", path: "Groups?count=-1", total: 1},
		{name: "negative start", path: "Users?startIndex=-1&count=1", total: 2, rows: 1},
		{name: "zero start", path: "Groups?startIndex=0&count=1", total: 1, rows: 1},
		{name: "large requested page", path: "Users?count=101", total: 2, rows: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := f.request(t, http.MethodGet, tc.path, "", "", http.StatusOK)
			var list struct {
				TotalResults int               `json:"totalResults"`
				StartIndex   int               `json:"startIndex"`
				ItemsPerPage int               `json:"itemsPerPage"`
				Resources    []json.RawMessage `json:"Resources"`
			}
			if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
				t.Fatal(err)
			}
			if list.TotalResults != tc.total || list.StartIndex != 1 || list.ItemsPerPage != tc.rows || list.Resources == nil || len(list.Resources) != tc.rows {
				t.Fatalf("page total=%d start=%d items=%d resources=%d", list.TotalResults, list.StartIndex, list.ItemsPerPage, len(list.Resources))
			}
		})
	}
	f.request(t, http.MethodGet, "Users?count=invalid", "", "", http.StatusBadRequest)
	f.request(t, http.MethodGet, "Groups?startIndex=invalid", "", "", http.StatusBadRequest)
}

func TestSCIMUserTombstoneAndInitialInactiveState(t *testing.T) {
	f := newSCIMFixture(t)
	u := f.user(t, "inactive", false)
	var active bool
	var profile, binding string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT du.active,u.display_name,um.status FROM directory_users du
		JOIN users u ON u.id=du.user_id JOIN user_members um ON um.user_id=du.user_id AND um.member_id=du.member_id
		WHERE du.id=$1`, u.ID).Scan(&active, &profile, &binding); err != nil {
		t.Fatal(err)
	}
	if active || binding != "revoked" || profile != "inactive" {
		t.Fatalf("initial inactive facts = %v, %s, %s", active, binding, profile)
	}
	u = scimResource(t, f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "replace", "path": "active", "value": true}), u.Meta.Version, 200))
	if !u.Active {
		t.Fatal("deactivation could not be reversed")
	}
	u = scimResource(t, f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "remove", "path": "displayName"}), u.Meta.Version, 200))
	if u.DisplayName != "" {
		t.Fatal("displayName removal was ignored")
	}
	f.request(t, "DELETE", "Users/"+u.ID, "", u.Meta.Version, 204)
	f.request(t, "GET", "Users/"+u.ID, "", "", 404)
	f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "replace", "path": "active", "value": true}), `W/"4"`, 404)
	f.request(t, "PUT", "Users/"+u.ID, `{"externalId":"inactive","userName":"inactive@scim.test","active":true}`, `W/"4"`, 404)
	f.request(t, "POST", "Users", `{"externalId":"inactive","userName":"different@scim.test"}`, "", 409)
	res := f.request(t, "GET", "Users", "", "", 200)
	if !strings.Contains(res.Body.String(), `"totalResults":0`) {
		t.Fatal("deleted user remained in collection")
	}
	var tombstone bool
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT deleted_at IS NOT NULL AND NOT active FROM directory_users WHERE id=$1`, u.ID).Scan(&tombstone); err != nil || !tombstone {
		t.Fatalf("user tombstone = %v, %v", tombstone, err)
	}
}

func TestSCIMExternalIDLookupSupportsVersionedLifecycleInEachDirectory(t *testing.T) {
	f := newSCIMFixture(t)
	other := f
	var err error
	other.directory, err = f.service.CreateDirectory(f.ctx, f.owner.ID, f.owner.SpaceID, enterprise.DirectoryInput{Name: "Partners"})
	if err != nil {
		t.Fatal(err)
	}
	const externalID = "Identity-42"
	for _, collection := range []string{"Users", "Groups"} {
		t.Run(collection, func(t *testing.T) {
			create := func(dir scimFixture, name string) scimTestResource {
				t.Helper()
				body := map[string]any{"externalId": externalID, "displayName": name}
				if collection == "Users" {
					body["userName"] = name + "@scim.test"
				}
				request, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				return scimResource(t, dir.request(t, http.MethodPost, collection, string(request), "", http.StatusCreated))
			}
			lookup := func(dir scimFixture, value, parameters string, wantTotal int) []scimTestResource {
				t.Helper()
				path := collection + "?filter=" + url.QueryEscape(value) + parameters
				response := dir.request(t, http.MethodGet, path, "", "", http.StatusOK)
				var result struct {
					Total     int                `json:"totalResults"`
					Resources []scimTestResource `json:"Resources"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Total != wantTotal || result.Resources == nil || len(result.Resources) > result.Total {
					t.Fatalf("unexpected collection total: got %d, want %d", result.Total, wantTotal)
				}
				return result.Resources
			}
			// The first SCIM group becomes the Space's root. Keep it in the
			// other directory so deleting the local leaf leaves it intact.
			foreign, local := create(other, "contractor"), create(f, "employee")
			const expression = `ExternalID EQ "Identity\u002d42"`
			first := lookup(f, expression, "", 1)
			second := lookup(other, expression, "", 1)
			if len(first) != 1 || first[0].ID != local.ID || first[0].Meta.Version != local.Meta.Version ||
				len(second) != 1 || second[0].ID != foreign.ID {
				t.Fatal("lookup did not bind each result and its version to its own directory")
			}
			if rows := lookup(f, expression, "&count=0", 1); len(rows) != 0 {
				t.Fatal("count-only query returned resources")
			}
			lookup(f, `externalId eq "identity-42"`, "", 0)
			lookup(f, `externalId eq " Identity-42"`, "", 0)
			for _, invalid := range []string{`externalId eq ""`, `externalId eq "wrong" or externalId eq "Identity-42"`} {
				response := f.request(t, http.MethodGet, collection+"?filter="+url.QueryEscape(invalid), "", "", http.StatusBadRequest)
				if !strings.Contains(response.Body.String(), `"scimType":"invalidFilter"`) {
					t.Fatal("malformed filter did not return invalidFilter")
				}
			}
			field, value := "displayName", any("Renamed")
			if collection == "Users" {
				field, value = "active", false
			}
			path := collection + "/" + first[0].ID
			updated := scimResource(t, f.request(t, http.MethodPatch, path,
				scimPatch(map[string]any{"op": "replace", "path": field, "value": value}),
				first[0].Meta.Version, http.StatusOK))
			after := lookup(f, expression, "", 1)
			if len(after) != 1 || after[0].Meta.Version != updated.Meta.Version || updated.Meta.Version == local.Meta.Version ||
				collection == "Users" && after[0].Active || collection == "Groups" && after[0].DisplayName != "Renamed" {
				t.Fatal("lookup did not expose the updated resource and version")
			}
			f.request(t, http.MethodDelete, path, "", after[0].Meta.Version, http.StatusNoContent)
			lookup(f, expression, "", 0)
			lookup(other, expression, "", 1)
		})
	}
}

func TestSCIMGroupPatchPreservesMembersAndManualSources(t *testing.T) {
	f := newSCIMFixture(t)
	u1, u2 := f.user(t, "alice", true), f.user(t, "bob", true)
	g := scimResource(t, f.request(t, "POST", "Groups", fmt.Sprintf(`{"externalId":"engineering","displayName":"Engineering","members":[{"value":%q}]}`, u1.ID), "", 201))
	if _, err := f.store.Pool.Exec(f.ctx, `INSERT INTO group_members(group_id,member_id,space_id,source)
		SELECT group_id,$2,$3,'manual' FROM directory_groups WHERE id=$1`, g.ID, f.owner.ID, f.owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	g = scimResource(t, f.request(t, "PATCH", "Groups/"+g.ID, scimPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Renamed"}), g.Meta.Version, 200))
	if len(g.Members) != 1 || g.Members[0].Value != u1.ID {
		t.Fatal("rename discarded directory members")
	}
	var groupName string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT g.name FROM groups g JOIN directory_groups dg ON dg.group_id=g.id WHERE dg.id=$1`, g.ID).Scan(&groupName); err != nil || groupName != "Renamed" {
		t.Fatalf("backing group name = %s, %v", groupName, err)
	}
	g = scimResource(t, f.request(t, "PATCH", "Groups/"+g.ID, scimPatch(
		map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": u2.ID}}},
		map[string]any{"op": "remove", "path": `members[value eq "` + u1.ID + `"]`},
	), g.Meta.Version, 200))
	if len(g.Members) != 1 || g.Members[0].Value != u2.ID {
		t.Fatalf("sequential member patch = %+v", g.Members)
	}
	var manual int
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM group_members gm JOIN directory_groups dg ON dg.group_id=gm.group_id
		WHERE dg.id=$1 AND gm.member_id=$2 AND gm.source='manual'`, g.ID, f.owner.ID).Scan(&manual); err != nil || manual != 1 {
		t.Fatalf("manual membership = %d, %v", manual, err)
	}
	child := scimResource(t, f.request(t, "POST", "Groups", `{"externalId":"sales","displayName":"Sales"}`, "", 201))
	listed := f.request(t, "GET", "Groups?count=1", "", "", 200)
	if !strings.Contains(listed.Body.String(), `"totalResults":2`) {
		t.Fatal("group collection omitted a live directory group")
	}
	f.request(t, "DELETE", "Groups/"+g.ID, "", g.Meta.Version, 409)
	f.request(t, "DELETE", "Groups/"+child.ID, "", child.Meta.Version, 204)
	f.request(t, "DELETE", "Groups/"+g.ID, "", g.Meta.Version, 204)
	f.request(t, "GET", "Groups/"+g.ID, "", "", 404)
	f.request(t, "POST", "Groups", `{"externalId":"engineering","displayName":"Recreated"}`, "", 409)
	f.request(t, "PATCH", "Groups/"+g.ID, scimPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Recreated"}), `W/"4"`, 404)
}

func TestSCIMGroupMembershipPatchReconcilesWithoutWritingNoOps(t *testing.T) {
	f := newSCIMFixture(t)
	first, second := f.user(t, "first", true), f.user(t, "second", true)
	created := f.request(t, http.MethodPost, "Groups", fmt.Sprintf(
		`{"externalId":"on-call","displayName":"On Call","members":[{"value":%q},{"value":%q}]}`, first.ID, second.ID),
		"", http.StatusCreated)
	group := scimResource(t, created)
	path := "Groups/" + group.ID
	lookup := func() (int64, int64) {
		t.Helper()
		var version, updates int64
		err := f.store.Pool.QueryRow(f.ctx, `SELECT policy_version,
			(SELECT count(*) FROM audit_logs WHERE space_id = $1 AND action = 'scim.group.update')
			FROM spaces WHERE id = $1`, f.owner.SpaceID).Scan(&version, &updates)
		if err != nil {
			t.Fatal(err)
		}
		return version, updates
	}
	policy, audits := lookup()
	addExisting := map[string]any{"op": "add", "path": "Members", "value": []any{map[string]any{"value": first.ID}}}
	absent := map[string]any{"op": "remove", "path": `Members[VaLuE EQ "not-a-member"]`}
	noOp := scimPatch(addExisting, absent)
	result := f.request(t, http.MethodPatch, path, noOp, group.Meta.Version, http.StatusOK)
	if result.Header().Get("ETag") != group.Meta.Version || result.Body.String() != created.Body.String() {
		t.Fatal("a repeated add and an absent-target remove changed the SCIM resource")
	}
	if current, written := lookup(); current != policy || written != audits {
		t.Fatal("a no-op PATCH changed the policy version or audit")
	}
	f.request(t, http.MethodPatch, path, noOp, `W/"999"`, http.StatusPreconditionFailed)

	// The selector's names are case insensitive, and the exact value can be JSON escaped.
	selector := `MEMBERS[ VaLuE   eQ   "\u0064` + first.ID[1:] + `" ]`
	remove := map[string]any{"op": "remove", "path": selector}
	invalid := map[string]any{"op": "remove", "path": `members[value co ""]`}
	rejected := f.request(t, http.MethodPatch, path, scimPatch(remove, invalid), group.Meta.Version, http.StatusBadRequest)
	if !strings.Contains(rejected.Body.String(), `"scimType":"invalidFilter"`) {
		t.Fatal("an unsupported selector did not return a SCIM filter error")
	}
	unchanged := f.request(t, http.MethodGet, path, "", "", http.StatusOK)
	if unchanged.Body.String() != created.Body.String() {
		t.Fatal("the invalid second operation applied the first removal")
	}
	updated := scimResource(t, f.request(t, http.MethodPatch, path, scimPatch(remove), group.Meta.Version, http.StatusOK))
	if updated.Meta.Version == group.Meta.Version || len(updated.Members) != 1 || updated.Members[0].Value != second.ID {
		t.Fatal("the selector did not remove just the requested member")
	}
	if current, written := lookup(); current <= policy || written != audits+1 {
		t.Fatal("the mutation did not record policy and audit changes")
	}
	result = f.request(t, http.MethodPatch, path, scimPatch(remove), updated.Meta.Version, http.StatusOK)
	if result.Header().Get("ETag") != updated.Meta.Version {
		t.Fatal("an absent-target retry changed the group version")
	}
}

func TestSCIMGroupPatchRequiresUnambiguousUserReferences(t *testing.T) {
	f := newSCIMFixture(t)
	user := f.user(t, "worker", true)
	group := scimResource(t, f.request(t, http.MethodPost, "Groups",
		`{"externalId":"audit","displayName":"Audit"}`, "", http.StatusCreated))
	path := "Groups/" + group.ID
	memberOperation := func(op string, member map[string]any) map[string]any {
		return map[string]any{"op": op, "path": "members", "value": []any{member}}
	}
	for _, member := range []map[string]any{
		{"value": user.ID, "type": "Group"},
		{"value": user.ID, "type": nil},
		{"value": user.ID, "type": "User", "Type": "User"},
		{"value": user.ID, "Value": user.ID},
	} {
		f.request(t, http.MethodPatch, path, scimPatch(memberOperation("add", member)), group.Meta.Version, http.StatusBadRequest)
	}
	admitted := scimResource(t, f.request(t, http.MethodPatch, path,
		scimPatch(memberOperation("add", map[string]any{"Value": user.ID, "TYPE": "uSeR"})),
		group.Meta.Version, http.StatusOK))
	if len(admitted.Members) != 1 || admitted.Members[0].Value != user.ID {
		t.Fatal("the SCIM group did not include its referenced directory user")
	}
	f.request(t, http.MethodPatch, path,
		scimPatch(memberOperation("remove", map[string]any{"value": user.ID, "type": "Group"})),
		admitted.Meta.Version, http.StatusBadRequest)
	current := scimResource(t, f.request(t, http.MethodGet, path, "", "", http.StatusOK))
	if len(current.Members) != 1 || current.Members[0].Value != user.ID || current.Meta.Version != admitted.Meta.Version {
		t.Fatal("an invalid reference removed a directory member")
	}
}

func TestSCIMGroupSyncRequiresCurrentConfiguratorAuthority(t *testing.T) {
	for _, kind := range []string{"permissions", "binding_rights", "reactivation", "missing_configurator", "self_escalation"} {
		t.Run(kind, func(t *testing.T) {
			f := newSCIMFixture(t)
			u := f.user(t, "target", true)
			g := scimResource(t, f.request(t, "POST", "Groups", `{"externalId":"privileged","displayName":"Privileged"}`, "", 201))
			var memberID, groupID string
			if err := f.store.Pool.QueryRow(f.ctx, `SELECT member_id FROM directory_users WHERE id=$1`, u.ID).Scan(&memberID); err != nil {
				t.Fatal(err)
			}
			if err := f.store.Pool.QueryRow(f.ctx, `SELECT group_id FROM directory_groups WHERE id=$1`, g.ID).Scan(&groupID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Pool.Exec(f.ctx, `INSERT INTO authorization_grants
				(id,space_id,permission_keys,grantee_group_id,scope,anchor_space_id,granted_by)
				VALUES ('grt_scim_inherited',$1,'["auth.members:read"]',$2,'space',$1,$3)`, f.owner.SpaceID, groupID, f.owner.ID); err != nil {
				t.Fatal(err)
			}
			if kind == "binding_rights" {
				if _, err := f.store.Pool.Exec(f.ctx, `INSERT INTO assign_rights(id,holder_member_id,permission_keys,anchor_space_id,source)
					VALUES ('ar_scim_member',$1,'["auth.members:read"]',$2,'system')`, memberID, f.owner.SpaceID); err != nil {
					t.Fatal(err)
				}
			}
			// An administrator with current coverage can provision this membership.
			patch := scimPatch(map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": u.ID}}})
			g = scimResource(t, f.request(t, "PATCH", "Groups/"+g.ID, patch, g.Meta.Version, 200))
			g = scimResource(t, f.request(t, "PATCH", "Groups/"+g.ID, scimPatch(map[string]any{"op": "remove", "path": "members"}), g.Meta.Version, 200))
			if kind == "reactivation" || kind == "binding_rights" {
				g = scimResource(t, f.request(t, "PATCH", "Groups/"+g.ID, patch, g.Meta.Version, 200))
				u = scimResource(t, f.request(t, "GET", "Users/"+u.ID, "", "", 200))
				u = scimResource(t, f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "replace", "path": "active", "value": false}), u.Meta.Version, 200))
			}
			if kind == "missing_configurator" {
				if _, err := f.store.Pool.Exec(f.ctx, `UPDATE directories SET configured_by_member_id=NULL,configured_by_user_id=NULL WHERE id=$1`, f.directory.ID); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := f.store.Pool.Exec(f.ctx, `UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=$1`, f.owner.ID); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "self_escalation" {
				// The configurator is also a directory member. Newly inherited
				// assignment rights must not be usable to cover this same write.
				if _, err := f.store.Pool.Exec(f.ctx, `UPDATE directories SET configured_by_member_id=$2,configured_by_user_id=(SELECT user_id FROM directory_users WHERE id=$3) WHERE id=$1`, f.directory.ID, memberID, u.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(f.ctx, `INSERT INTO authorization_grants(id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
                VALUES ('grt_scim_self_admin',$1,'["auth.connections:manage"]',$2,'space',$1,$3)`, f.owner.SpaceID, memberID, f.owner.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(f.ctx, `UPDATE authorization_grants SET permission_keys='["auth.members:read","auth.grants:assign"]' WHERE id='grt_scim_inherited'`); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.Pool.Exec(f.ctx, `INSERT INTO assign_rights(id,holder_member_id,permission_keys,anchor_space_id,source)
                VALUES ('ar_scim_self',$1,'["*"]',$2,'system')`, memberID, f.owner.SpaceID); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "reactivation" || kind == "binding_rights" {
				f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "replace", "path": "active", "value": true}), u.Meta.Version, 403)
			} else {
				f.request(t, "PATCH", "Groups/"+g.ID, patch, g.Meta.Version, 403)
				got := scimResource(t, f.request(t, "GET", "Groups/"+g.ID, "", "", 200))
				if len(got.Members) != 0 || got.Meta.Version != g.Meta.Version {
					t.Fatal("rejected delta changed directory facts")
				}
			}
		})
	}
}

func TestSCIMDeactivationRevokesAgentSubtreeAndRollsBackOnAuditFailure(t *testing.T) {
	f := newSCIMFixture(t)
	u := f.user(t, "owner", true)
	var userID, memberID string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT user_id,member_id FROM directory_users WHERE id=$1`, u.ID).Scan(&userID, &memberID); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: f.store}
	parent, parentKey, err := agents.Create(f.ctx, agent.CreateInput{OwnerMemberID: memberID, CreatedByUser: userID, Name: "parent"})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(f.ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	sibling, _, err := agents.Create(f.ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "unrelated"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(f.ctx, `CREATE FUNCTION reject_scim_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='scim.user.update' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_scim_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_scim_audit()`); err != nil {
		t.Fatal(err)
	}
	patch := scimPatch(map[string]any{"op": "replace", "path": "active", "value": false})
	f.request(t, "PATCH", "Users/"+u.ID, patch, u.Meta.Version, 503)
	got := scimResource(t, f.request(t, "GET", "Users/"+u.ID, "", "", 200))
	if !got.Active || got.Meta.Version != u.Meta.Version {
		t.Fatal("audit failure committed deactivation")
	}
	var states []string
	for _, id := range []string{parent.ID, child.ID} {
		var state string
		if err := f.store.Pool.QueryRow(f.ctx, `SELECT status FROM members WHERE id=$1`, id).Scan(&state); err != nil {
			t.Fatal(err)
		}
		states = append(states, state)
	}
	if !slices.Equal(states, []string{"active", "active"}) {
		t.Fatal("audit failure left a partially suspended subtree")
	}
	if _, err := f.store.Pool.Exec(f.ctx, `DROP TRIGGER reject_scim_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	u = scimResource(t, f.request(t, "PATCH", "Users/"+u.ID, patch, u.Meta.Version, 200))
	f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "replace", "path": "active", "value": true}), u.Meta.Version, 200)
	for _, id := range []string{parent.ID, child.ID, sibling.ID} {
		var state string
		if err := f.store.Pool.QueryRow(f.ctx, `SELECT status FROM members WHERE id=$1`, id).Scan(&state); err != nil {
			t.Fatal(err)
		}
		want := "suspended"
		if id == sibling.ID {
			want = "active"
		}
		if state != want {
			t.Fatalf("Agent %s state = %s, want %s", id, state, want)
		}
	}
	for _, key := range []string{parentKey, childKey} {
		if _, err := agents.AuthenticateKey(f.ctx, key); err == nil {
			t.Fatal("deactivation left an Agent credential usable")
		}
	}
	var count int
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_logs WHERE space_id=$1 AND actor_type='directory'
		AND action IN ('scim.user.update','agent.binding.suspend')`, f.owner.SpaceID).Scan(&count); err != nil || count < 2 {
		t.Fatalf("tenant-visible lifecycle audits = %d, %v", count, err)
	}
}

func TestSCIMRejectsTokenRotatedWhileWaitingForDirectoryLock(t *testing.T) {
	for _, method := range []string{"GET", "PATCH"} {
		t.Run(method, func(t *testing.T) {
			f := newSCIMFixture(t)
			u := f.user(t, "waiting", true)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			locked, release := make(chan struct{}), make(chan struct{})
			writer := make(chan error, 1)
			go func() {
				writer <- f.store.InTx(ctx, func(q *db.Queries) error {
					if _, err := q.LockDirectory(ctx, db.LockDirectoryParams{ID: f.directory.ID}); err != nil {
						return err
					}
					close(locked)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					_, err := q.RotateDirectoryToken(ctx, db.RotateDirectoryTokenParams{ID: f.directory.ID, Version: f.directory.Version,
						TokenHash: []byte("replacement-hash"), TokenPrefix: "replacement-prefix"})
					return err
				})
			}()
			<-locked
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				req := httptest.NewRequest(method, "/scim/v2/"+f.directory.ID+"/Users/"+u.ID,
					strings.NewReader(scimPatch(map[string]any{"op": "replace", "path": "displayName", "value": "unwanted"}))).WithContext(ctx)
				req.Header.Set("Authorization", "Bearer "+f.directory.Token.Value())
				req.Header.Set("Content-Type", "application/scim+json")
				req.Header.Set("If-Match", u.Meta.Version)
				res := httptest.NewRecorder()
				f.handler.ServeHTTP(res, req)
				result <- res
			}()
			for {
				var waiting bool
				if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
					WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%directories%FOR%')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case res := <-result:
					t.Fatalf("request bypassed held directory lock: %d", res.Code)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			close(release)
			if err := <-writer; err != nil {
				t.Fatal(err)
			}
			res := <-result
			if res.Code != 401 {
				t.Fatalf("rotated token after lock wait = %d: %s", res.Code, res.Body.String())
			}
		})
	}
}

func TestSCIMRejectsCrossDirectoryReferencesAndUnsupportedPatch(t *testing.T) {
	f := newSCIMFixture(t)
	u := f.user(t, "local", true)
	other, err := f.service.CreateDirectory(f.ctx, f.owner.ID, f.owner.SpaceID, enterprise.DirectoryInput{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	second := f
	second.directory = other
	second.request(t, "GET", "Users/"+u.ID, "", "", 404)
	second.directory.Token = f.directory.Token
	second.request(t, "GET", "Users", "", "", 401)
	second.directory.Token = other.Token
	f.request(t, "GET", "Groups?filter=members%20eq%20%22example%22", "", "", 400)
	second.request(t, "POST", "Groups", fmt.Sprintf(`{"externalId":"cross","displayName":"Cross","members":[{"value":%q}]}`, u.ID), "", 400)
	f.request(t, "GET", `Groups?filter=displayName%20co%20%22x%22`, "", "", 400)
	f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "replace", "value": map[string]any{"unknown": true}}), u.Meta.Version, 400)
	f.request(t, "PATCH", "Users/"+u.ID, scimPatch(map[string]any{"op": "replace", "path": "userName", "value": ""}), u.Meta.Version, 400)
	f.request(t, "PATCH", "Users/"+u.ID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]}`, u.Meta.Version, 400)
	got := scimResource(t, f.request(t, "GET", "Users/"+u.ID, "", "", 200))
	if got.Meta.Version != u.Meta.Version || got.DisplayName != u.DisplayName {
		t.Fatal("invalid PATCH changed resource")
	}
}

func TestSCIMDirectoryGroupLookupFiltersAndOmitsMembers(t *testing.T) {
	f := newSCIMFixture(t)
	const displayName = `Engineering "Core"`
	member := f.user(t, "engineer", true)
	create := func(target scimFixture, externalID string, members []map[string]string) scimTestResource {
		t.Helper()
		body, err := json.Marshal(map[string]any{"externalId": externalID, "displayName": displayName, "members": members})
		if err != nil {
			t.Fatal(err)
		}
		return scimResource(t, target.request(t, http.MethodPost, "Groups", string(body), "", http.StatusCreated))
	}
	original := create(f, "engineering", []map[string]string{{"value": member.ID}})
	const userID = "usr_scim_admin"
	_, otherOwner, err := f.service.Authorization.CreateSpace(t.Context(), userID, "Other Space", "other-space")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(t.Context(), `INSERT INTO authorization_grants
		(id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_scim_second_directory',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, otherOwner.SpaceID, otherOwner.ID); err != nil {
		t.Fatal(err)
	}
	otherCtx := authorization.WithHumanActor(t.Context(), otherOwner.ID, userID)
	other, err := f.service.CreateDirectory(otherCtx, otherOwner.ID, otherOwner.SpaceID, enterprise.DirectoryInput{Name: "Second directory"})
	if err != nil {
		t.Fatal(err)
	}
	second := f
	second.directory = other
	foreign := create(second, "other-engineering", nil)
	filter := "Groups?filter=" + url.QueryEscape(`DisplayName EQ "engineering \"CORE\""`)
	list := func(target scimFixture, path string, wantTotal int, wantIDs ...string) []map[string]json.RawMessage {
		t.Helper()
		res := target.request(t, http.MethodGet, path, "", "", http.StatusOK)
		var view struct {
			TotalResults, ItemsPerPage int
			Resources                  []map[string]json.RawMessage
		}
		if err := json.Unmarshal(res.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if view.TotalResults != wantTotal || view.ItemsPerPage != len(wantIDs) || len(view.Resources) != len(wantIDs) {
			t.Fatalf("unexpected group list total=%d items=%d", view.TotalResults, view.ItemsPerPage)
		}
		for i, id := range wantIDs {
			var actual string
			if err := json.Unmarshal(view.Resources[i]["id"], &actual); err != nil || actual != id {
				t.Fatal("group query returned an unexpected resource")
			}
		}
		return view.Resources
	}
	one := list(f, filter, 1, original.ID)[0]
	if !strings.Contains(string(one["members"]), member.ID) {
		t.Fatal("default group projection lost the member")
	}
	excluded := list(f, filter+"&excludedAttributes=members", 1, original.ID)[0]
	if _, present := excluded["members"]; present {
		t.Fatal("filtered list returned the excluded members field")
	}
	list(f, filter+"&count=0", 1)
	list(f, filter+"&startIndex=2", 1)
	list(second, filter, 1, foreign.ID)
	list(f, "Groups?filter="+url.QueryEscape(`displayName eq "Engineering"`), 0)
	group := f.request(t, http.MethodGet, "Groups/"+original.ID+"?excludedAttributes=members", "", "", http.StatusOK)
	var detail map[string]json.RawMessage
	if err := json.Unmarshal(group.Body.Bytes(), &detail); err != nil ||
		detail["members"] != nil || group.Header().Get("ETag") != original.Meta.Version {
		t.Fatal("group detail did not omit members and preserve resource version")
	}
	for _, bad := range []string{`displayName eq "x" or displayName eq "y"`, `displayName eq 10`, `displayName eq "\u0000"`} {
		res := f.request(t, http.MethodGet, "Groups?filter="+url.QueryEscape(bad), "", "", http.StatusBadRequest)
		if !strings.Contains(res.Body.String(), `"scimType":"invalidFilter"`) {
			t.Fatal("invalid group filter did not return a SCIM invalidFilter")
		}
	}
	f.request(t, http.MethodDelete, "Groups/"+original.ID, "", original.Meta.Version, http.StatusNoContent)
	list(f, filter, 0)
	list(second, filter, 1, foreign.ID)
}

func TestSCIMUserReplacementRejectsAccountTakeover(t *testing.T) {
	f := newSCIMFixture(t)
	u := f.user(t, "replace", true)
	u = scimResource(t, f.request(t, "PUT", "Users/"+u.ID,
		`{"externalId":"replace","userName":" CHANGED@scim.test ","displayName":"Updated","active":true}`, u.Meta.Version, 200))
	var email, profile string
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT u.email_normalized,u.display_name FROM users u JOIN directory_users du ON du.user_id=u.id WHERE du.id=$1`, u.ID).Scan(&email, &profile); err != nil {
		t.Fatal(err)
	}
	if email != "changed@scim.test" || profile != "Updated" {
		t.Fatalf("replaced account facts = %s, %s", email, profile)
	}
	f.request(t, "PUT", "Users/"+u.ID, `{"externalId":"replace","userName":"admin@scim.test","active":true}`, u.Meta.Version, 409)
	f.request(t, "POST", "Users", `{"externalId":"takeover","userName":"ADMIN@scim.test"}`, "", 409)
	f.request(t, "PUT", "Users/"+u.ID, `{"externalId":"different","userName":"changed@scim.test","active":true}`, u.Meta.Version, 400)
	got := scimResource(t, f.request(t, "GET", "Users/"+u.ID, "", "", 200))
	if got.Meta.Version != u.Meta.Version {
		t.Fatal("rejected identity update changed its version")
	}
}

func TestSCIMGroupMutationRollsBackFactsVersionAndAudit(t *testing.T) {
	f := newSCIMFixture(t)
	u := f.user(t, "rollback", true)
	g := scimResource(t, f.request(t, "POST", "Groups", `{"externalId":"stable","displayName":"Stable"}`, "", 201))
	var version int64
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT policy_version FROM spaces WHERE id=$1`, f.owner.SpaceID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(f.ctx, `CREATE FUNCTION reject_scim_group_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action LIKE 'scim.group.%' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_scim_group_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_scim_group_audit()`); err != nil {
		t.Fatal(err)
	}
	f.request(t, "PATCH", "Groups/"+g.ID, scimPatch(map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": u.ID}}}), g.Meta.Version, 503)
	f.request(t, "DELETE", "Groups/"+g.ID, "", g.Meta.Version, 503)
	f.request(t, "POST", "Groups", `{"externalId":"uncommitted","displayName":"Uncommitted"}`, "", 503)
	got := scimResource(t, f.request(t, "GET", "Groups/"+g.ID, "", "", 200))
	if got.Meta.Version != g.Meta.Version || len(got.Members) != 0 {
		t.Fatal("failed audit committed group changes")
	}
	var current int64
	var groups int
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT policy_version FROM spaces WHERE id=$1`, f.owner.SpaceID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM directory_groups WHERE directory_id=$1`, f.directory.ID).Scan(&groups); err != nil {
		t.Fatal(err)
	}
	if current != version || groups != 1 {
		t.Fatalf("audit failure left policy version %d (was %d) or %d groups", current, version, groups)
	}
}

func TestSCIMDeactivationIncludesAgentCreatedDuringSynchronization(t *testing.T) {
	f := newSCIMFixture(t)
	u := f.user(t, "concurrent-owner", true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var userID, memberID string
	if err := f.store.Pool.QueryRow(ctx, `SELECT user_id,member_id FROM directory_users WHERE id=$1`, u.ID).Scan(&userID, &memberID); err != nil {
		t.Fatal(err)
	}
	barrier, err := f.store.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Release()
	if _, err := barrier.Exec(ctx, `SELECT pg_advisory_lock(963127)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = barrier.Exec(context.Background(), `SELECT pg_advisory_unlock(963127)`) }()
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION hold_scim_agent_creation() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.type='agent' THEN PERFORM pg_advisory_xact_lock(963127); END IF; RETURN NEW; END $$;
		CREATE TRIGGER hold_scim_agent_creation BEFORE INSERT ON members FOR EACH ROW EXECUTE FUNCTION hold_scim_agent_creation()`); err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: f.store}
	type creationResult struct {
		agent agent.Agent
		key   string
		err   error
	}
	created := make(chan creationResult, 1)
	go func() {
		a, key, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: memberID, CreatedByUser: userID, Name: "concurrent"})
		created <- creationResult{a, key, err}
	}()
	wait := func(query string) {
		t.Helper()
		for {
			var waiting bool
			if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)`, query).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	wait("%INSERT INTO members%")
	deactivated := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("PATCH", "/scim/v2/"+f.directory.ID+"/Users/"+u.ID,
			strings.NewReader(scimPatch(map[string]any{"op": "replace", "path": "active", "value": false}))).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+f.directory.Token.Value())
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("If-Match", u.Meta.Version)
		res := httptest.NewRecorder()
		f.handler.ServeHTTP(res, req)
		deactivated <- res
	}()
	wait("%members%FOR UPDATE%")
	if _, err := barrier.Exec(ctx, `SELECT pg_advisory_unlock(963127)`); err != nil {
		t.Fatal(err)
	}
	result := <-created
	if result.err != nil {
		t.Fatal(result.err)
	}
	if res := <-deactivated; res.Code != 200 {
		t.Fatalf("concurrent deactivation = %d: %s", res.Code, res.Body.String())
	}
	var status string
	if err := f.store.Pool.QueryRow(ctx, `SELECT status FROM members WHERE id=$1`, result.agent.ID).Scan(&status); err != nil || status != "suspended" {
		t.Fatalf("concurrently created Agent escaped revocation: %s, %v", status, err)
	}
	if _, err := agents.AuthenticateKey(ctx, result.key); err == nil {
		t.Fatal("concurrent Agent credential escaped revocation")
	}
}
