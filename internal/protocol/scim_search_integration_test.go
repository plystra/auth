package protocol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
)

func TestSCIMSearchUsesDirectoryScopedReadOnlyCollections(t *testing.T) {
	f := newSCIMFixture(t)
	f.handler = route.Middleware(route.Principal, f.handler)
	alice := f.user(t, "alice", true)
	f.user(t, "bob", true)
	const admin = "usr_scim_admin"
	_, otherOwner, err := f.service.Authorization.CreateSpace(t.Context(), admin, "Other workforce", "other-workforce")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(t.Context(), `INSERT INTO authorization_grants
		(id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_search_other_directory',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, otherOwner.SpaceID, otherOwner.ID); err != nil {
		t.Fatal(err)
	}
	otherCtx := authorization.WithHumanActor(t.Context(), otherOwner.ID, admin)
	other, err := f.service.CreateDirectory(otherCtx, otherOwner.ID, otherOwner.SpaceID, enterprise.DirectoryInput{Name: "Other workforce"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f
	foreign.directory = other
	foreign.user(t, "outsider", true)
	group := scimResource(t, f.request(t, http.MethodPost, "Groups",
		`{"externalId":"engineering","displayName":"Engineering","members":[{"value":"`+alice.ID+`"}]}`, "", http.StatusCreated))
	scimResource(t, foreign.request(t, http.MethodPost, "Groups", `{"externalId":"engineering","displayName":"Engineering"}`, "", http.StatusCreated))

	type searchPage struct {
		TotalResults, StartIndex, ItemsPerPage int
		Schemas                                []string
		Resources                              []map[string]json.RawMessage
	}
	search := func(kind string, fields map[string]any) searchPage {
		t.Helper()
		fields["schemas"] = []string{scimSearchSchema}
		body, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		response := f.request(t, http.MethodPost, kind+"/.search", string(body), "", http.StatusOK)
		var page searchPage
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil ||
			len(page.Schemas) != 1 || page.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" ||
			page.Resources == nil || page.ItemsPerPage != len(page.Resources) {
			t.Fatal("invalid SCIM search page")
		}
		return page
	}
	user := search("Users", map[string]any{
		"filter": `userName eq "ALICE@scim.test"`, "attributes": []string{"userName", "meta.version"}, "startIndex": 0, "count": 1,
	})
	if user.TotalResults != 1 || user.StartIndex != 1 || user.ItemsPerPage != 1 ||
		len(user.Resources[0]) != 4 || string(user.Resources[0]["userName"]) != `"alice@scim.test"` {
		t.Fatal("SCIM search changed the user filter, projection, or pagination")
	}
	total := search("Users", map[string]any{"count": 0})
	if total.TotalResults != 2 || total.ItemsPerPage != 0 {
		t.Fatal("count zero did not preserve directory-scoped totals")
	}
	second := search("Users", map[string]any{"startIndex": 2, "count": 1})
	if second.StartIndex != 2 || second.ItemsPerPage != 1 || string(second.Resources[0]["userName"]) != `"bob@scim.test"` {
		t.Fatal("second page did not preserve collection ordering")
	}
	groups := search("Groups", map[string]any{"filter": `displayName eq "engineering"`, "excludedAttributes": []string{"members"}})
	if groups.TotalResults != 1 || groups.ItemsPerPage != 1 || groups.Resources[0]["members"] != nil {
		t.Fatal("group search exposed omitted members or a foreign directory")
	}
	members := search("Groups", map[string]any{"attributes": []string{scimGroup + ":members.value"}})
	if len(members.Resources) != 1 || len(members.Resources[0]) != 3 ||
		string(members.Resources[0]["members"]) != `[{"value":"`+alice.ID+`"}]` {
		t.Fatal("group search did not project member subattributes")
	}

	const request = `{"schemas":["` + scimSearchSchema + `"]}`
	for _, body := range []string{
		`{"filter":"externalId eq \"alice\""}`,
		`{"schemas":["invalid"]}`,
		`{"schemas":["` + scimSearchSchema + `"],"attributes":["id"],"excludedAttributes":["meta"]}`,
		`{"schemas":["` + scimSearchSchema + `"],"sortBy":"userName"}`,
		`{"schemas":["` + scimSearchSchema + `"],"count":1.5}`,
		`{"schemas":["` + scimSearchSchema + `"],"attributes":["userName,displayName"]}`,
		request + `{}`,
		request + strings.Repeat(" ", scimSearchLimit),
	} {
		f.request(t, http.MethodPost, "Users/.search", body, "", http.StatusBadRequest)
	}
	f.request(t, http.MethodPost, "Users/.search?count=0", request, "", http.StatusBadRequest)
	invalid := f.request(t, http.MethodPost, "Groups/.search", `{"schemas":["`+scimSearchSchema+`"],"filter":"displayName co \"engine\""}`, "", http.StatusBadRequest)
	if !strings.Contains(invalid.Body.String(), `"scimType":"invalidFilter"`) {
		t.Fatal("unsupported group search filter did not use the SCIM error type")
	}
	cross := httptest.NewRequest(http.MethodPost, "/scim/v2/"+other.ID+"/Users/.search", strings.NewReader(request))
	cross.Header.Set("Authorization", "Bearer "+f.directory.Token.Value())
	cross.Header.Set("Content-Type", "application/scim+json")
	denied := httptest.NewRecorder()
	f.handler.ServeHTTP(denied, cross)
	if denied.Code != http.StatusUnauthorized || denied.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatal("search accepted a foreign directory token")
	}
	for _, resource := range []scimTestResource{alice, group} {
		path := strings.TrimPrefix(resource.Meta.Location, "/scim/v2/"+f.directory.ID+"/")
		if f.request(t, http.MethodGet, path, "", "", http.StatusOK).Header().Get("ETag") != resource.Meta.Version {
			t.Fatal("body-based search advanced a resource version")
		}
	}
}
