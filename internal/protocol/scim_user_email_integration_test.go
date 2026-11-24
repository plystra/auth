package protocol

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/plystra/auth/internal/enterprise"
)

func TestSCIMEmailProfileIsVersionedAndIndependentFromLogin(t *testing.T) {
	f := newSCIMFixture(t)
	const username = "employee@scim.test"
	type userResource struct {
		ID       string
		UserName string
		Emails   []enterprise.SCIMEmail
		Meta     struct{ Version string }
	}
	decode := func(raw []byte) userResource {
		t.Helper()
		var user userResource
		if err := json.Unmarshal(raw, &user); err != nil || user.ID == "" || user.Meta.Version == "" || user.UserName != username {
			t.Fatal("invalid directory user response")
		}
		return user
	}
	created := decode(f.request(t, http.MethodPost, "Users",
		`{"externalId":"email-fixture","userName":"employee@scim.test","emails":[
			{"value":"Work@Scim.Test","type":"Work","display":"Office","primary":true},
			{"value":"admin@scim.test","type":"home"}]}`,
		"", http.StatusCreated).Body.Bytes())
	path := "Users/" + created.ID
	work := enterprise.SCIMEmail{Value: "work@scim.test", Type: "work", Display: "Office", Primary: true}
	home := enterprise.SCIMEmail{Value: "admin@scim.test", Type: "home"}
	if !slices.Equal(created.Emails, []enterprise.SCIMEmail{work, home}) {
		t.Fatal("creation omitted or changed directory addresses")
	}
	var page struct{ Resources []userResource }
	if err := json.Unmarshal(f.request(t, http.MethodGet, "Users", "", "", http.StatusOK).Body.Bytes(), &page); err != nil ||
		len(page.Resources) != 1 || !slices.Equal(page.Resources[0].Emails, created.Emails) {
		t.Fatal("list did not return the same addresses")
	}
	other, err := f.service.CreateDirectory(f.ctx, f.owner.ID, f.owner.SpaceID, enterprise.DirectoryInput{Name: "Other directory"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f
	foreign.directory = other
	foreign.request(t, http.MethodGet, path, "", "", http.StatusNotFound)

	patch := scimPatch(
		map[string]any{"op": "replace", "path": `Emails[TYPE EQ "WORK"].VALUE`, "value": "new-work@scim.test"},
		map[string]any{"op": "remove", "path": `emails[type eq "home"]`},
		map[string]any{"op": "add", "path": `emails[type eq "other"].value`, "value": "other@scim.test"},
		map[string]any{"op": "add", "value": map[string]any{"Emails": []any{map[string]any{"value": "new-home@scim.test", "type": "home", "primary": true}}}},
	)
	f.request(t, http.MethodPatch, path, patch, `W/"999"`, http.StatusPreconditionFailed)
	updated := decode(f.request(t, http.MethodPatch, path, patch, created.Meta.Version, http.StatusOK).Body.Bytes())
	work.Value, work.Primary = "new-work@scim.test", false
	otherEmail := enterprise.SCIMEmail{Value: "other@scim.test", Type: "other"}
	home.Value, home.Primary = "new-home@scim.test", true
	if updated.Meta.Version == created.Meta.Version || !slices.Equal(updated.Emails, []enterprise.SCIMEmail{work, otherEmail, home}) {
		t.Fatal("PATCH did not apply ordered changes with one primary address")
	}
	failed := f.request(t, http.MethodPatch, path, scimPatch(
		map[string]any{"op": "remove", "path": "emails"},
		map[string]any{"op": "replace", "path": `emails[type eq "work"].value`, "value": "new@scim.test"},
	), updated.Meta.Version, http.StatusBadRequest)
	var problem struct{ SCIMType string }
	if err := json.Unmarshal(failed.Body.Bytes(), &problem); err != nil || problem.SCIMType != "noTarget" {
		t.Fatal("missing email target did not return the SCIM error type")
	}
	for _, addresses := range []string{
		`[{"value":"not an address"}]`,
		`[{"value":"a@scim.test","unknown":true}]`,
		`[{"value":"a@scim.test","type":"HOME"},{"value":"A@SCIM.TEST","type":"home"}]`,
		`[{"value":"a@scim.test","primary":true},{"value":"b@scim.test","primary":true}]`,
	} {
		f.request(t, http.MethodPatch, path, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"emails","value":`+addresses+`}]}`, updated.Meta.Version, http.StatusBadRequest)
	}
	current := decode(f.request(t, http.MethodGet, path, "", "", http.StatusOK).Body.Bytes())
	if current.Meta.Version != updated.Meta.Version || !slices.Equal(current.Emails, updated.Emails) {
		t.Fatal("failed operation modified the email profile")
	}
	var accountEmail string
	if err := f.store.Pool.QueryRow(t.Context(), `SELECT u.email FROM users u JOIN directory_users d ON d.user_id=u.id WHERE d.id=$1`, created.ID).Scan(&accountEmail); err != nil || accountEmail != username {
		t.Fatal("directory email profile changed the login address")
	}
	cleared := decode(f.request(t, http.MethodPut, path, `{"externalId":"email-fixture","userName":"employee@scim.test"}`, updated.Meta.Version, http.StatusOK).Body.Bytes())
	if len(cleared.Emails) != 0 {
		t.Fatal("PUT without emails retained directory addresses")
	}
	reassigned := decode(f.request(t, http.MethodPatch, path, scimPatch(map[string]any{"op": "add", "path": `emails[type eq "work"].value`, "value": "work@scim.test"}), cleared.Meta.Version, http.StatusOK).Body.Bytes())
	f.request(t, http.MethodDelete, path, "", reassigned.Meta.Version, http.StatusNoContent)
	var empty bool
	if err := f.store.Pool.QueryRow(t.Context(), `SELECT scim_emails='[]'::jsonb FROM directory_users WHERE id=$1`, created.ID).Scan(&empty); err != nil || !empty {
		t.Fatal("tombstone retained directory email addresses")
	}
}

func TestSCIMDiscoveryDeclaresEmailProfileAttributes(t *testing.T) {
	f := newSCIMFixture(t)
	response := f.request(t, http.MethodGet, "Schemas/"+scimUser, "", "", http.StatusOK)
	type attribute struct {
		Name, Type    string
		MultiValued   bool
		SubAttributes []attribute
	}
	var user struct{ Attributes []attribute }
	if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	for _, field := range user.Attributes {
		if field.Name == "emails" && field.Type == "complex" && field.MultiValued {
			var fields []string
			for _, sub := range field.SubAttributes {
				fields = append(fields, sub.Name+":"+sub.Type)
			}
			if slices.Equal(fields, []string{"value:string", "type:string", "display:string", "primary:boolean"}) {
				return
			}
		}
	}
	t.Fatal("schema omitted email profile attributes")
}
