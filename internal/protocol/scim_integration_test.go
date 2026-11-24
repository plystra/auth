package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/credential"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/route"
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

	mux := route.NewMux()
	(HTTP{Enterprise: svc}).Register(mux)
	handler := route.MiddlewareWithIdempotency(route.Principal, mux, st, (credential.Validator{Directory: svc}).Validate)
	postUser := func(token, key, payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/"+directory.ID+"/Users", strings.NewReader(payload))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("Idempotency-Key", key)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	const createPayload = `{"externalId":"idp-1","userName":"Alice@Example.test","displayName":"Alice","active":true}`
	const createKey = "scim-user-create"
	created := postUser(directory.Token.Value(), createKey, createPayload)
	if created.Code != http.StatusCreated {
		t.Fatalf("SCIM user create = %d %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), directory.Token.Value()) {
		t.Fatal("SCIM token leaked in resource response")
	}
	replayed := postUser(directory.Token.Value(), createKey, createPayload)
	if replayed.Code != http.StatusCreated || replayed.Header().Get("Idempotency-Replayed") != "true" || replayed.Body.String() != created.Body.String() {
		t.Fatal("current directory token could not replay its own successful SCIM operation")
	}
	other, err := svc.CreateDirectory(requestCtx, owner.ID, space.ID, enterprise.DirectoryInput{Name: "Other directory"})
	if err != nil {
		t.Fatal(err)
	}
	assertDenied := func(token string) {
		t.Helper()
		result := postUser(token, createKey, createPayload)
		if result.Code != http.StatusUnauthorized || result.Header().Get("Idempotency-Replayed") != "" ||
			result.Header().Get("Content-Type") != "application/scim+json" || !strings.Contains(result.Body.String(), "urn:ietf:params:scim:api:messages:2.0:Error") {
			t.Fatal("a missing, foreign or revoked credential did not receive a SCIM authentication error")
		}
	}
	assertDenied("")
	assertDenied(other.Token.Value())
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
		handler.ServeHTTP(res, req)
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
	handler.ServeHTTP(wrongResponse, wrongVersion)
	if wrongResponse.Code != http.StatusPreconditionFailed {
		t.Fatalf("SCIM version conflict = %d %s", wrongResponse.Code, wrongResponse.Body.String())
	}

	patchUser := func(version string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPatch, "/scim/v2/"+directory.ID+"/Users/"+user.ID, strings.NewReader(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":false}]}`))
		req.Header.Set("Authorization", "Bearer "+directory.Token.Value())
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("If-Match", version)
		req.Header.Set("Idempotency-Key", "scim-user-offboarding")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	patchResponse := patchUser(`W/"1"`)
	if patchResponse.Code != http.StatusOK || !strings.Contains(patchResponse.Body.String(), `"active":false`) {
		t.Fatalf("SCIM user deactivation = %d %s", patchResponse.Code, patchResponse.Body.String())
	}
	if replay := patchUser(`W/"1"`); replay.Code != http.StatusOK || replay.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal("a retry with the original SCIM version did not replay its successful result")
	}
	if conflict := patchUser(`W/"2"`); conflict.Code != http.StatusConflict || conflict.Header().Get("Content-Type") != "application/scim+json" {
		t.Fatal("a changed If-Match did not produce a SCIM idempotency conflict")
	}
	var bindingStatus string
	if err := st.Pool.QueryRow(ctx, `SELECT status FROM user_members WHERE member_id = (SELECT member_id FROM directory_users WHERE id = $1)`, user.ID).Scan(&bindingStatus); err != nil {
		t.Fatal(err)
	}
	if bindingStatus != "revoked" {
		t.Fatalf("SCIM deactivation binding status = %q, want revoked", bindingStatus)
	}
	secondResponse := postUser(directory.Token.Value(), "", `{"externalId":"idp-2","userName":"bob@example.test","displayName":"Bob","active":true}`)
	if secondResponse.Code != http.StatusCreated {
		t.Fatalf("second SCIM user create = %d %s", secondResponse.Code, secondResponse.Body.String())
	}
	var secondUser struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(secondResponse.Body.Bytes(), &secondUser); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		filter string
		status int
		want   string
	}{
		{`userName eq "bob@example.test"`, http.StatusOK, `"totalResults":1`},
		{`userName eq "Bob\u0040example.test"`, http.StatusOK, `"totalResults":1`},
		{`displayName eq "Bob"`, http.StatusBadRequest, `"scimType":"invalidFilter"`},
		{`userName eq "bob@@example.test"`, http.StatusBadRequest, `"scimType":"invalidFilter"`},
		{`userName eq "bob@example.test" or userName eq "anyone@example.test"`, http.StatusBadRequest, `"scimType":"invalidFilter"`},
	} {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/"+directory.ID+"/Users?count=1&filter="+url.QueryEscape(tc.filter), nil)
		req.Header.Set("Authorization", "Bearer "+directory.Token.Value())
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != tc.status || !strings.Contains(res.Body.String(), tc.want) {
			t.Fatalf("SCIM filter %q returned HTTP %d, want %d and %s", tc.filter, res.Code, tc.status, tc.want)
		}
	}
	postGroup := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/"+directory.ID+"/Groups", strings.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+directory.Token.Value())
		req.Header.Set("Content-Type", "application/scim+json")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
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
	handler.ServeHTTP(putGroupResponse, putGroup)
	if putGroupResponse.Code != http.StatusOK {
		t.Fatalf("SCIM group replace = %d %s", putGroupResponse.Code, putGroupResponse.Body.String())
	}
	patchGroup := httptest.NewRequest(http.MethodPatch, "/scim/v2/"+directory.ID+"/Groups/"+group.ID, strings.NewReader(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Engineering Final"}]}`))
	patchGroup.Header.Set("Authorization", "Bearer "+directory.Token.Value())
	patchGroup.Header.Set("Content-Type", "application/scim+json")
	patchGroup.Header.Set("If-Match", `W/"2"`)
	patchGroupResponse := httptest.NewRecorder()
	handler.ServeHTTP(patchGroupResponse, patchGroup)
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
	assertDenied(directory.Token.Value())
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
