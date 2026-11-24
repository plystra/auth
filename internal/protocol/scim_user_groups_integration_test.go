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

func TestSCIMDirectoryGroupSyncContinuesThroughOffboarding(t *testing.T) {
	f := newSCIMFixture(t)
	departed, incoming := f.user(t, "departed-worker", true), f.user(t, "incoming-worker", true)
	group := scimResource(t, f.request(t, http.MethodPost, "Groups", fmt.Sprintf(
		`{"externalId":"desk","displayName":"Desk","members":[{"value":%q}]}`, departed.ID), "", http.StatusCreated))
	other := scimResource(t, f.request(t, http.MethodPost, "Groups", `{"externalId":"other","displayName":"Other"}`, "", http.StatusCreated))
	userPath, groupPath := "Users/"+departed.ID, "Groups/"+group.ID
	current := scimResource(t, f.request(t, http.MethodGet, userPath, "", "", http.StatusOK))
	disabled := f.request(t, http.MethodPatch, userPath,
		scimPatch(map[string]any{"op": "replace", "path": "active", "value": false}), current.Meta.Version, http.StatusOK)
	disabledVersion := disabled.Header().Get("ETag")
	if !strings.Contains(disabled.Body.String(), fmt.Sprintf(`"value":%q`, group.ID)) {
		t.Fatal("disabling the user discarded the desired directory relationship")
	}
	add := func(id string) string {
		return scimPatch(map[string]any{
			"op": "add", "path": "members", "value": []map[string]string{{"value": id}},
		})
	}
	f.request(t, http.MethodPatch, "Groups/"+other.ID, add(departed.ID), other.Meta.Version, http.StatusBadRequest)
	updated := scimResource(t, f.request(t, http.MethodPatch, groupPath, add(incoming.ID), group.Meta.Version, http.StatusOK))
	if len(updated.Members) != 2 {
		t.Fatal("adding an active employee discarded the existing disabled employee's directory relationship")
	}
	if _, err := f.store.Pool.Exec(f.ctx, `CREATE FUNCTION reject_offboarding_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='scim.user.delete' THEN RAISE EXCEPTION 'owned audit fixture'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_offboarding_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_offboarding_audit()`); err != nil {
		t.Fatal(err)
	}
	f.request(t, http.MethodDelete, userPath, "", disabledVersion, http.StatusServiceUnavailable)
	unchanged := scimResource(t, f.request(t, http.MethodGet, groupPath, "", "", http.StatusOK))
	if unchanged.Meta.Version != updated.Meta.Version || len(unchanged.Members) != 2 {
		t.Fatal("a failed delete changed the group's membership or version")
	}
	if _, err := f.store.Pool.Exec(f.ctx, `DROP TRIGGER reject_offboarding_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	f.request(t, http.MethodDelete, userPath, "", disabledVersion, http.StatusNoContent)
	f.request(t, http.MethodGet, userPath, "", "", http.StatusNotFound)
	remaining := scimResource(t, f.request(t, http.MethodGet, groupPath, "", "", http.StatusOK))
	if remaining.Meta.Version == updated.Meta.Version || len(remaining.Members) != 1 || remaining.Members[0].Value != incoming.ID {
		t.Fatal("deleting the departed employee did not version and remove only their directory group relationship")
	}
	f.request(t, http.MethodPatch, groupPath, add(incoming.ID), updated.Meta.Version, http.StatusPreconditionFailed)
	f.request(t, http.MethodPatch, groupPath, add(departed.ID), remaining.Meta.Version, http.StatusBadRequest)
	var sources int
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM group_members gm
		JOIN directory_groups dg ON dg.group_id=gm.group_id
		JOIN directory_users du ON du.member_id=gm.member_id AND du.directory_id=dg.directory_id
		WHERE dg.id=$1 AND du.id=$2 AND gm.source='directory'`, group.ID, departed.ID).Scan(&sources); err != nil || sources != 0 {
		t.Fatal("deletion retained the departed employee's native directory source")
	}
}
