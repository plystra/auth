package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestSCIMDirectoryProvisioningRotationAndRevocation(t *testing.T) {
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
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status) VALUES ('usr_scim_owner', 'scim-owner@example.test', 'scim-owner@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	space, owner, err := authorizer.CreateSpace(ctx, "usr_scim_owner", "SCIM Space", "scim-space")
	if err != nil {
		t.Fatal(err)
	}
	grantID := string(ids.New[ids.GrantID]("grt"))
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ($1, $2, '["auth.connections:manage"]'::jsonb, $3, 'space', $2, $3)
	`, grantID, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	svc := &enterprise.Service{Store: st, Authorization: authorizer, Passwords: security.DefaultPasswordHasher(), DataKey: secret.New(strings.Repeat("d", 32))}
	requestCtx := authorization.WithHumanActor(ctx, owner.ID, "usr_scim_owner")
	directory, err := svc.CreateDirectory(requestCtx, owner.ID, space.ID, enterprise.DirectoryInput{Name: "Workforce"})
	if err != nil {
		t.Fatal(err)
	}
	if directory.Token.Value() == "" {
		t.Fatal("directory creation did not return a token")
	}
	var storedHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM directories WHERE id = $1`, directory.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if string(storedHash) == directory.Token.Value() {
		t.Fatal("SCIM token was stored in plaintext")
	}

	var mux http.ServeMux
	(HTTP{Enterprise: svc}).Register(&mux)
	postUser := func(token string, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/"+directory.ID+"/Users", strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/scim+json")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	created := postUser(directory.Token.Value(), `{"externalId":"idp-1","userName":"Alice@Example.test","displayName":"Alice","active":true}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("SCIM user create = %d %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), directory.Token.Value()) {
		t.Fatal("SCIM token leaked in resource response")
	}
	var user struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
		Meta   struct {
			Version string `json:"version"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || !user.Active || user.Meta.Version != `W/"1"` {
		t.Fatalf("unexpected SCIM user resource: %+v", user)
	}

	get := func(token, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/"+directory.ID+"/Users/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	if response := get(directory.Token.Value(), user.ID); response.Code != http.StatusOK {
		t.Fatalf("SCIM user get = %d %s", response.Code, response.Body.String())
	}
	wrongVersion := httptest.NewRequest(http.MethodPatch, "/scim/v2/"+directory.ID+"/Users/"+user.ID, strings.NewReader(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Changed"}]}`))
	wrongVersion.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	wrongVersion.Header.Set("Content-Type", "application/scim+json")
	wrongVersion.Header.Set("If-Match", `W/"9"`)
	wrongResponse := httptest.NewRecorder()
	mux.ServeHTTP(wrongResponse, wrongVersion)
	if wrongResponse.Code != http.StatusPreconditionFailed {
		t.Fatalf("SCIM version conflict = %d %s", wrongResponse.Code, wrongResponse.Body.String())
	}

	patchUser := httptest.NewRequest(http.MethodPatch, "/scim/v2/"+directory.ID+"/Users/"+user.ID, strings.NewReader(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":false}]}`))
	patchUser.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	patchUser.Header.Set("Content-Type", "application/scim+json")
	patchUser.Header.Set("If-Match", `W/"1"`)
	patchResponse := httptest.NewRecorder()
	mux.ServeHTTP(patchResponse, patchUser)
	if patchResponse.Code != http.StatusOK || !strings.Contains(patchResponse.Body.String(), `"active":false`) {
		t.Fatalf("SCIM user deactivation = %d %s", patchResponse.Code, patchResponse.Body.String())
	}
	var bindingStatus string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM user_members WHERE member_id = (SELECT member_id FROM directory_users WHERE id = $1)`, user.ID).Scan(&bindingStatus); err != nil {
		t.Fatal(err)
	}
	if bindingStatus != "revoked" {
		t.Fatalf("SCIM deactivation binding status = %q, want revoked", bindingStatus)
	}
	secondResponse := postUser(directory.Token.Value(), `{"externalId":"idp-2","userName":"bob@example.test","displayName":"Bob","active":true}`)
	if secondResponse.Code != http.StatusCreated {
		t.Fatalf("second SCIM user create = %d %s", secondResponse.Code, secondResponse.Body.String())
	}
	var secondUser struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(secondResponse.Body.Bytes(), &secondUser); err != nil {
		t.Fatal(err)
	}
	filteredRequest := httptest.NewRequest(http.MethodGet, "/scim/v2/"+directory.ID+`/Users?filter=userName%20eq%20%22bob%40example.test%22&count=1`, nil)
	filteredRequest.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	filteredResponse := httptest.NewRecorder()
	mux.ServeHTTP(filteredResponse, filteredRequest)
	if filteredResponse.Code != http.StatusOK || !strings.Contains(filteredResponse.Body.String(), `"totalResults":1`) {
		t.Fatalf("SCIM user filter = %d %s", filteredResponse.Code, filteredResponse.Body.String())
	}
	invalidFilterRequest := httptest.NewRequest(http.MethodGet, "/scim/v2/"+directory.ID+`/Users?filter=displayName%20eq%20%22Bob%22`, nil)
	invalidFilterRequest.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	invalidFilterResponse := httptest.NewRecorder()
	mux.ServeHTTP(invalidFilterResponse, invalidFilterRequest)
	if invalidFilterResponse.Code != http.StatusBadRequest || !strings.Contains(invalidFilterResponse.Body.String(), "invalidFilter") {
		t.Fatalf("unsupported SCIM filter = %d %s", invalidFilterResponse.Code, invalidFilterResponse.Body.String())
	}
	postGroup := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/"+directory.ID+"/Groups", strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+directory.Token.Value())
		req.Header.Set("Content-Type", "application/scim+json")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	groupResponse := postGroup(`{"externalId":"group-1","displayName":"Engineering","members":[{"value":"` + secondUser.ID + `"}]}`)
	if groupResponse.Code != http.StatusCreated {
		t.Fatalf("SCIM group create = %d %s", groupResponse.Code, groupResponse.Body.String())
	}
	var group struct {
		ID   string `json:"id"`
		Meta struct {
			Version string `json:"version"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(groupResponse.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO group_members (group_id, member_id, space_id, source) SELECT group_id, $1, $2, 'manual' FROM directory_groups WHERE id = $3`, owner.ID, space.ID, group.ID); err != nil {
		t.Fatal(err)
	}
	putGroup := httptest.NewRequest(http.MethodPut, "/scim/v2/"+directory.ID+"/Groups/"+group.ID, strings.NewReader(`{"externalId":"group-1","displayName":"Engineering Updated","members":[{"value":"`+secondUser.ID+`"}]}`))
	putGroup.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	putGroup.Header.Set("Content-Type", "application/scim+json")
	putGroup.Header.Set("If-Match", group.Meta.Version)
	putGroupResponse := httptest.NewRecorder()
	mux.ServeHTTP(putGroupResponse, putGroup)
	if putGroupResponse.Code != http.StatusOK {
		t.Fatalf("SCIM group replace = %d %s", putGroupResponse.Code, putGroupResponse.Body.String())
	}
	patchGroup := httptest.NewRequest(http.MethodPatch, "/scim/v2/"+directory.ID+"/Groups/"+group.ID, strings.NewReader(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Engineering Final"}]}`))
	patchGroup.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	patchGroup.Header.Set("Content-Type", "application/scim+json")
	patchGroup.Header.Set("If-Match", `W/"2"`)
	patchGroupResponse := httptest.NewRecorder()
	mux.ServeHTTP(patchGroupResponse, patchGroup)
	if patchGroupResponse.Code != http.StatusOK || !strings.Contains(patchGroupResponse.Body.String(), "Engineering Final") {
		t.Fatalf("SCIM group PATCH operations = %d %s", patchGroupResponse.Code, patchGroupResponse.Body.String())
	}
	var manualCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = (SELECT group_id FROM directory_groups WHERE id = $1) AND member_id = $2 AND source = 'manual'`, group.ID, owner.ID).Scan(&manualCount); err != nil {
		t.Fatal(err)
	}
	if manualCount != 1 {
		t.Fatal("SCIM group sync removed a manual membership")
	}

	rotated, err := svc.RotateDirectoryToken(requestCtx, owner.ID, space.ID, directory.ID, directory.Version)
	if err != nil {
		t.Fatal(err)
	}
	if get(directory.Token.Value(), user.ID).Code != http.StatusUnauthorized {
		t.Fatal("old SCIM token remained valid after rotation")
	}
	if get(rotated.Token.Value(), user.ID).Code != http.StatusOK {
		t.Fatal("rotated SCIM token was not accepted")
	}
	if err := svc.DisableDirectory(requestCtx, owner.ID, space.ID, directory.ID, rotated.Version); err != nil {
		t.Fatal(err)
	}
	if get(rotated.Token.Value(), user.ID).Code != http.StatusUnauthorized {
		t.Fatal("disabled SCIM directory still accepted requests")
	}
}
