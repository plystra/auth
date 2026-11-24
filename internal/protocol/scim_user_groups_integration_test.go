package protocol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestSCIMUserGroupsTracksVersionedDirectoryMembership(t *testing.T) {
	f := newSCIMFixture(t)
	user, unaffected := f.user(t, "group-worker", true), f.user(t, "other-worker", true)
	userPath, unaffectedPath := "Users/"+user.ID, "Users/"+unaffected.ID
	group := scimResource(t, f.request(t, http.MethodPost, "Groups", fmt.Sprintf(
		`{"externalId":"readers","displayName":"Readers","members":[{"value":%q}]}`, user.ID), "", http.StatusCreated))
	groupPath := "Groups/" + group.ID
	groupRef := "/scim/v2/" + f.directory.ID + "/" + groupPath

	current := func() string {
		t.Helper()
		response := f.request(t, http.MethodGet, userPath, "", "", http.StatusOK)
		var body struct {
			Active bool
			Groups []map[string]string
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || !body.Active || len(body.Groups) != 1 ||
			body.Groups[0]["value"] != group.ID || body.Groups[0]["$ref"] != groupRef || body.Groups[0]["type"] != "direct" {
			t.Fatal("SCIM User did not identify its direct directory Group")
		}
		return response.Header().Get("ETag")
	}
	added := current()
	if added == "" || added == user.Meta.Version {
		t.Fatal("initial group membership did not advance its user's ETag")
	}
	if _, err := f.store.Pool.Exec(f.ctx, `INSERT INTO group_members(group_id,member_id,space_id,source)
		SELECT dg.group_id,du.member_id,$3,'manual' FROM directory_groups dg
		JOIN directory_users du ON du.directory_id=dg.directory_id WHERE dg.id=$1 AND du.id=$2`,
		group.ID, unaffected.ID, f.owner.SpaceID); err != nil {
		t.Fatal(err)
	}
	unaffectedResponse := f.request(t, http.MethodGet, unaffectedPath, "", "", http.StatusOK)
	if unaffectedResponse.Header().Get("ETag") != unaffected.Meta.Version || strings.Contains(unaffectedResponse.Body.String(), `"groups":`) {
		t.Fatal("a manual membership appeared as a directory relationship")
	}
	for _, path := range []string{userPath + "?attributes=groups.%24ref", "Users?attributes=groups.%24ref"} {
		projected := f.request(t, http.MethodGet, path, "", "", http.StatusOK).Body.String()
		if !strings.Contains(projected, fmt.Sprintf(`"$ref":%q`, groupRef)) || strings.Contains(projected, `"value":`) {
			t.Fatal("SCIM projection did not isolate the requested group reference")
		}
	}
	search := f.request(t, http.MethodPost, "Users/.search", `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"attributes":["groups.value"]
	}`, "", http.StatusOK).Body.String()
	if !strings.Contains(search, fmt.Sprintf(`"value":%q`, group.ID)) || strings.Contains(search, `"$ref":`) {
		t.Fatal("SCIM search did not return the projected group")
	}
	withoutGroups := f.request(t, http.MethodGet, userPath+"?excludedAttributes=groups", "", "", http.StatusOK)
	if strings.Contains(withoutGroups.Body.String(), `"groups":`) || withoutGroups.Header().Get("ETag") != added {
		t.Fatal("excluding groups changed the resource version or returned the omitted attribute")
	}

	update := scimPatch(map[string]any{"op": "replace", "path": "active", "value": false})
	f.request(t, http.MethodPatch, userPath, update, user.Meta.Version, http.StatusPreconditionFailed)
	rejected := f.request(t, http.MethodPatch, userPath, scimPatch(
		map[string]any{"op": "replace", "path": "active", "value": false},
		map[string]any{"op": "remove", "path": "groups"},
	), added, http.StatusBadRequest)
	if !strings.Contains(rejected.Body.String(), `"scimType":"mutability"`) || current() != added {
		t.Fatal("a user mutation changed an attribute read-only on User or committed part of its patch")
	}
	renamed := scimResource(t, f.request(t, http.MethodPatch, groupPath, scimPatch(
		map[string]any{"op": "replace", "path": "displayName", "value": "Renamed"},
	), group.Meta.Version, http.StatusOK))
	if current() != added {
		t.Fatal("renaming a group changed the user's direct relationship")
	}
	repeated := f.request(t, http.MethodPatch, groupPath, scimPatch(map[string]any{
		"op": "add", "path": "members", "value": []map[string]string{{"value": user.ID}},
	}), renamed.Meta.Version, http.StatusOK)
	if repeated.Header().Get("ETag") != renamed.Meta.Version || current() != added {
		t.Fatal("repeated group synchronization advanced the group's or user's version")
	}
	body := f.request(t, http.MethodGet, userPath, "", "", http.StatusOK).Body.String()
	f.request(t, http.MethodPut, userPath, body, added, http.StatusOK)
	afterRoundTrip := current()
	if afterRoundTrip == added {
		t.Fatal("the existing versioned PUT did not commit")
	}
	f.request(t, http.MethodDelete, groupPath, "", renamed.Meta.Version, http.StatusNoContent)
	removed := f.request(t, http.MethodGet, userPath, "", "", http.StatusOK)
	if strings.Contains(removed.Body.String(), `"groups":`) || removed.Header().Get("ETag") == afterRoundTrip {
		t.Fatal("deleting a group did not update the current user's membership and version")
	}
}

func TestSCIMDiscoveryDeclaresUserGroupsReadOnly(t *testing.T) {
	f := newSCIMFixture(t)
	response := f.request(t, http.MethodGet, "Schemas/"+scimUser, "", "", http.StatusOK)
	var schema struct {
		Attributes []struct {
			Name, Type, Mutability string
			MultiValued            bool
			SubAttributes          []struct{ Name, Type, Mutability string }
		}
	}
	if err := json.Unmarshal(response.Body.Bytes(), &schema); err != nil {
		t.Fatal(err)
	}
	for _, attribute := range schema.Attributes {
		if attribute.Name != "groups" {
			continue
		}
		if attribute.Type != "complex" || attribute.Mutability != "readOnly" || !attribute.MultiValued {
			t.Fatal("groups is not declared as a read-only complex array")
		}
		fields := map[string]string{"value": "string", "$ref": "reference", "type": "string"}
		for _, field := range attribute.SubAttributes {
			if fields[field.Name] != field.Type || field.Mutability != "readOnly" {
				t.Fatal("invalid groups subattribute")
			}
			delete(fields, field.Name)
		}
		if len(fields) != 0 {
			t.Fatal("the User schema omitted a group membership field")
		}
		return
	}
	t.Fatal("the User schema omitted groups")
}
