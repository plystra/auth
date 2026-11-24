package protocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/enterprise"
)

func TestSCIMUserProjectionPreservesVersionsAndDirectoryIsolation(t *testing.T) {
	f := newSCIMFixture(t)
	with := func(path string, query url.Values) string { return path + "?" + query.Encode() }
	const body = `{"externalId":"projection","userName":"projection@example.test","displayName":"Private Label",
		"name":{"givenName":"Alice","familyName":"Hidden"},
		"emails":[{"value":"hidden@example.test","type":"work","primary":true}]}`
	read := func(data []byte) map[string]json.RawMessage {
		t.Helper()
		var resource map[string]json.RawMessage
		if err := json.Unmarshal(data, &resource); err != nil || resource["id"] == nil || resource["schemas"] == nil {
			t.Fatal("projected resource omitted its ID or schema")
		}
		return resource
	}
	created := f.request(t, http.MethodPost, with("Users", url.Values{"attributes": {scimUser + ":NAME.givenName"}}), body, "", http.StatusCreated)
	resource := read(created.Body.Bytes())
	if len(resource) != 3 || string(resource["name"]) != `{"givenName":"Alice"}` ||
		created.Header().Get("ETag") == "" || created.Header().Get("Location") == "" {
		t.Fatal("the projected creation lost version headers or returned private attributes")
	}
	var id string
	if err := json.Unmarshal(resource["id"], &id); err != nil {
		t.Fatal(err)
	}
	path := "Users/" + id
	version := created.Header().Get("ETag")
	selected := with(path, url.Values{"attributes": {"emails.TYPE,meta.version,unregistered"}})
	review := f.request(t, http.MethodGet, selected, "", "", http.StatusOK)
	resource = read(review.Body.Bytes())
	var meta map[string]string
	if err := json.Unmarshal(resource["meta"], &meta); err != nil {
		t.Fatal(err)
	}
	if len(resource) != 4 || string(resource["emails"]) != `[{"type":"work"}]` ||
		len(meta) != 1 || meta["version"] != version || review.Header().Get("ETag") != version {
		t.Fatal("selected subattributes or version differ from the request")
	}
	other, err := f.service.CreateDirectory(f.ctx, f.owner.ID, f.owner.SpaceID, enterprise.DirectoryInput{Name: "Other directory"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f
	foreign.directory = other
	foreign.request(t, http.MethodGet, selected, "", "", http.StatusNotFound)
	excluded := with(path, url.Values{"excludedAttributes": {"schemas,id,emails.value,name.familyName,displayname,meta"}})
	redacted := f.request(t, http.MethodGet, excluded, "", "", http.StatusOK)
	resource = read(redacted.Body.Bytes())
	if len(resource) != 7 || resource["meta"] != nil || resource["displayName"] != nil ||
		strings.Contains(redacted.Body.String(), "hidden@example.test") || strings.Contains(redacted.Body.String(), "Hidden") ||
		redacted.Header().Get("ETag") != version || redacted.Header().Get("Location") != created.Header().Get("Location") {
		t.Fatal("exclusion did not preserve metadata headers and hide selected fields")
	}
	var page struct {
		TotalResults, StartIndex, ItemsPerPage int
		Resources                              []map[string]json.RawMessage
	}
	filtered := with("Users", url.Values{"attributes": {"USERName"}, "filter": {`externalId eq "projection"`}, "count": {"1"}})
	list := f.request(t, http.MethodGet, filtered, "", "", http.StatusOK)
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil || page.TotalResults != 1 || page.StartIndex != 1 ||
		page.ItemsPerPage != 1 || len(page.Resources) != 1 || len(page.Resources[0]) != 3 || page.Resources[0]["userName"] == nil {
		t.Fatal("list projection changed filter or pagination results")
	}
	for _, query := range []url.Values{
		{"attributes": {"userName"}, "excludedAttributes": {"emails"}},
		{"attributes": {"emails", "meta"}},
		{"excludedAttributes": {"emails,"}},
		{"excludedAttributes": {`emails[type eq "work"]`}},
		{"attributes": {strings.Repeat("id,", 64) + "name"}},
	} {
		f.request(t, http.MethodPut, with(path, query), body, version, http.StatusBadRequest)
	}
	if latest := f.request(t, http.MethodGet, path, "", "", http.StatusOK); latest.Header().Get("ETag") != version {
		t.Fatal("invalid response projection advanced the version")
	}
	patch := scimPatch(map[string]any{"op": "replace", "path": "displayName", "value": "Updated"})
	changed := f.request(t, http.MethodPatch, with(path, url.Values{"attributes": {"id"}}), patch, version, http.StatusOK)
	if len(read(changed.Body.Bytes())) != 2 || changed.Header().Get("ETag") == version {
		t.Fatal("projected PATCH failed to expose the new ETag")
	}
	f.request(t, http.MethodPatch, path, patch, version, http.StatusPreconditionFailed)
}
