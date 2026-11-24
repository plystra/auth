package protocol

import (
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/enterprise"
)

func TestSCIMStructuredNameSupportsVersionedDirectoryLifecycle(t *testing.T) {
	f := newSCIMFixture(t)
	const username = "employee@scim.test"
	created := scimResource(t, f.request(t, http.MethodPost, "Users",
		`{"externalId":"name-fixture","userName":"employee@scim.test","displayName":"Directory Employee",
		"name":{"GIVENNAME":"Élodie","familyName":"López","middleName":"J","honorificPrefix":"Dr.","honorificSuffix":null,"formatted":"Dr. Élodie López"}}`,
		"", http.StatusCreated))
	path := "Users/" + created.ID
	expect := func(user scimTestResource, fields map[string]string) {
		t.Helper()
		if user.UserName != username || user.DisplayName != "Directory Employee" || !maps.Equal(user.Name, fields) {
			t.Fatal("unexpected structured name or unrelated account attribute change")
		}
	}
	want := map[string]string{"givenName": "Élodie", "familyName": "López", "middleName": "J",
		"honorificPrefix": "Dr.", "formatted": "Dr. Élodie López"}
	expect(created, want)
	var list struct{ Resources []scimTestResource }
	page := f.request(t, http.MethodGet, "Users", "", "", http.StatusOK)
	if err := json.Unmarshal(page.Body.Bytes(), &list); err != nil || len(list.Resources) != 1 {
		t.Fatal("failed to read the protected directory collection")
	}
	expect(list.Resources[0], want)

	other, err := f.service.CreateDirectory(f.ctx, f.owner.ID, f.owner.SpaceID, enterprise.DirectoryInput{Name: "Other directory"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f
	foreign.directory = other
	foreign.request(t, http.MethodGet, path, "", "", http.StatusNotFound)
	foreign.directory.Token = f.directory.Token
	foreign.request(t, http.MethodGet, "Users", "", "", http.StatusUnauthorized)

	patch := scimPatch(
		map[string]any{"op": "replace", "value": map[string]any{"NAME": map[string]any{"GivenName": "Ana"}}},
		map[string]any{"op": "remove", "path": "name.middleName"},
		map[string]any{"op": "add", "path": "Name.HonorificSuffix", "value": "III"},
	)
	f.request(t, http.MethodPatch, path, patch, `W/"999"`, http.StatusPreconditionFailed)
	updated := scimResource(t, f.request(t, http.MethodPatch, path, patch, created.Meta.Version, http.StatusOK))
	delete(want, "middleName")
	want["givenName"], want["honorificSuffix"] = "Ana", "III"
	expect(updated, want)
	if updated.Meta.Version == created.Meta.Version {
		t.Fatal("structured update did not advance ETag")
	}
	for _, value := range []any{true, strings.Repeat("é", 129), "break\nline"} {
		bad := scimPatch(
			map[string]any{"op": "remove", "path": "name"},
			map[string]any{"op": "replace", "path": "name.givenName", "value": value},
		)
		f.request(t, http.MethodPatch, path, bad, updated.Meta.Version, http.StatusBadRequest)
	}
	unchanged := scimResource(t, f.request(t, http.MethodGet, path, "", "", http.StatusOK))
	expect(unchanged, want)
	if unchanged.Meta.Version != updated.Meta.Version {
		t.Fatal("invalid composite PATCH changed the resource")
	}
	put := scimResource(t, f.request(t, http.MethodPut, path,
		`{"externalId":"name-fixture","userName":"employee@scim.test","displayName":"Directory Employee","name":{"familyName":"Surname"}}`,
		updated.Meta.Version, http.StatusOK))
	expect(put, map[string]string{"familyName": "Surname"})
	cleared := scimResource(t, f.request(t, http.MethodPatch, path,
		scimPatch(map[string]any{"op": "remove", "path": "name"}),
		put.Meta.Version, http.StatusOK))
	expect(cleared, nil)
	reassigned := scimResource(t, f.request(t, http.MethodPatch, path,
		scimPatch(map[string]any{"op": "add", "path": "name.givenName", "value": "Ana"}),
		cleared.Meta.Version, http.StatusOK))
	f.request(t, http.MethodDelete, path, "", reassigned.Meta.Version, http.StatusNoContent)
	f.request(t, http.MethodGet, path, "", "", http.StatusNotFound)
	var empty bool
	if err := f.store.Pool.QueryRow(t.Context(), "SELECT scim_name = '{}'::jsonb FROM directory_users WHERE id = $1", created.ID).Scan(&empty); err != nil || !empty {
		t.Fatal("tombstone retained structured name contents")
	}
}

func TestSCIMDiscoveryDeclaresStructuredNameAttributes(t *testing.T) {
	f := newSCIMFixture(t)
	result := f.request(t, http.MethodGet, "Schemas/"+scimUser, "", "", http.StatusOK)
	type attribute struct {
		Name, Type    string
		SubAttributes []attribute
	}
	var schema struct{ Attributes []attribute }
	if err := json.Unmarshal(result.Body.Bytes(), &schema); err != nil {
		t.Fatal(err)
	}
	for _, field := range schema.Attributes {
		if field.Name == "name" {
			var names []string
			for _, sub := range field.SubAttributes {
				if sub.Type != "string" {
					t.Fatal("invalid structured name sub-attribute type")
				}
				names = append(names, sub.Name)
			}
			if field.Type == "complex" && strings.Join(names, ",") == "formatted,familyName,givenName,middleName,honorificPrefix,honorificSuffix" {
				return
			}
		}
	}
	t.Fatal("schema does not describe the supported structured name")
}
