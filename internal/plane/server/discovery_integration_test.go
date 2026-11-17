package server

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
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/ids"
	"github.com/plystra/auth/internal/route"
)

func TestServerDiscoveryReturnsOnlyAuthenticatedKeyMetadata(t *testing.T) {
	ctx := context.Background()
	st, authz, _, spaceID, raw, _ := newServerFixture(t)
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	request := discoveryHTTP(t, &API{Applications: apps})
	// Discovery needs no permission grant and does not substitute for authz.check.
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET scopes = '[]'::jsonb WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	response := request("/server/v1/key", raw, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("key identity = %d %s", response.Code, response.Body.String())
	}
	var out keyIdentityOutput
	if err := json.Unmarshal(response.Body.Bytes(), &out.Body); err != nil {
		t.Fatal(err)
	}
	key := out.Body.Data
	if !ids.APIKeyID(key.ID).Valid() || key.ApplicationID != "app_server_test" || key.ClientID != "server-test-client" || key.SpaceID != spaceID ||
		key.Name != "server-test" || key.Prefix != strings.SplitN(raw, ".", 2)[0] || !key.AllowSubjectAssertion ||
		len(key.Grants) != 0 || len(key.RestrictTo) != 1 || key.RestrictTo[0].SpaceID != spaceID || key.RestrictTo[0].IncludeDescendants ||
		len(key.AllowedIPCIDRs) != 0 || key.CreatedAt.IsZero() || !key.ExpiresAt.After(time.Now()) {
		t.Fatalf("unexpected authenticated key metadata: %+v", key)
	}
	var used bool
	if err := st.Pool.QueryRow(ctx, `SELECT last_used_at IS NOT NULL FROM api_keys WHERE id = $1`, key.ID).Scan(&used); err != nil || !used {
		t.Fatalf("key authentication did not record use: %v", err)
	}
	page := readDiscoveryInstallations(t, request("/server/v1/installations", raw, nil))
	if len(page.Body.Data) != 1 || page.Body.Data[0].SpaceID != spaceID || page.Body.NextCursor != "" {
		t.Fatalf("grant-free installation discovery = %+v", page.Body)
	}
}

func TestServerInstallationDiscoveryFiltersBeforePaginationAndRechecksScope(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, raw, _ := newServerFixture(t)
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	request := discoveryHTTP(t, &API{Applications: apps})
	if _, err := st.Pool.Exec(ctx, `UPDATE applications SET visibility = 'public', review_status = 'approved' WHERE id = 'app_server_test'`); err != nil {
		t.Fatal(err)
	}
	var initialID string
	if err := st.Pool.QueryRow(ctx, `SELECT id FROM application_installations WHERE application_id = 'app_server_test'`).Scan(&initialID); err != nil {
		t.Fatal(err)
	}
	expected := []string{initialID}
	var customerSpaceID string
	for _, slug := range []string{"discovery-customer", "discovery-other-customer"} {
		space, owner, err := authz.CreateSpace(ctx, "usr_server_actor", slug, slug)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
			(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
			VALUES ($1, $2, '["auth.applications:manage"]'::jsonb, $3, 'space', $2, $3)`, string(ids.New[ids.GrantID]("grt")), space.ID, owner.ID); err != nil {
			t.Fatal(err)
		}
		scope := "space"
		if customerSpaceID == "" {
			customerSpaceID, scope = space.ID, "space_tree"
		}
		installed, err := apps.Install(ctx, owner.ID, "app_server_test", space.ID, scope, "")
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, installed.ID)
	}
	child, _, err := authz.CreateSpace(ctx, "usr_server_actor", "Discovery child", "discovery-child")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET parent_id = $1 WHERE id = $2`, customerSpaceID, child.ID); err != nil {
		t.Fatal(err)
	}
	other, err := apps.Register(ctx, actor.ID, application.RegisterInput{
		SpaceID: spaceID, Name: "Other publisher application", ManifestPermissions: []string{"auth.authz:check"},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherInstallation, err := apps.InstallSpace(ctx, actor.ID, other.ID, spaceID)
	if err != nil {
		t.Fatal(err)
	}
	limited := readDiscoveryInstallations(t, request("/server/v1/installations?limit=1", raw, nil))
	if len(limited.Body.Data) != 1 || limited.Body.Data[0].SpaceID != spaceID || limited.Body.NextCursor != "" {
		t.Fatalf("restricted key leaked another customer or application: %+v", limited.Body)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = '[]'::jsonb WHERE name = 'server-test'`); err != nil {
		t.Fatal(err)
	}
	var actual []string
	var firstCursor string
	path := "/server/v1/installations?limit=1"
	for range 4 {
		response := request(path, raw, nil)
		page := readDiscoveryInstallations(t, response)
		if len(page.Body.Data) != 1 {
			t.Fatalf("pagination page = %+v", page.Body)
		}
		installation := page.Body.Data[0]
		if installation.ApplicationID != "app_server_test" || installation.ID == otherInstallation.ID || installation.SpaceID == child.ID || installation.Status != "active" || len(installation.ApprovedPermissions) != 3 {
			t.Fatalf("unexpected visible installation: %+v", installation)
		}
		actual = append(actual, installation.ID)
		if firstCursor == "" {
			firstCursor = page.Body.NextCursor
		}
		if page.Body.NextCursor == "" {
			break
		}
		path = "/server/v1/installations?limit=1&cursor=" + url.QueryEscape(page.Body.NextCursor)
	}
	slices.Sort(expected)
	if !slices.Equal(actual, expected) || firstCursor == "" {
		t.Fatalf("visible pages = %v, want %v with a cursor", actual, expected)
	}
	expiresAt := time.Now().Add(time.Hour)
	otherRaw, err := apps.CreateKey(ctx, "app_server_test", "another-key", []string{"auth.authz:check"}, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	deniedCursor := request("/server/v1/installations?cursor="+url.QueryEscape(firstCursor), otherRaw, nil)
	if deniedCursor.Code != http.StatusBadRequest || !strings.Contains(deniedCursor.Body.String(), "VALIDATION_FAILED") {
		t.Fatalf("cursor reused with another key = %d %s", deniedCursor.Code, deniedCursor.Body.String())
	}
	for _, query := range []string{"cursor=invalid", "limit=0", "limit=101", "cursor=" + base64.RawURLEncoding.EncodeToString([]byte("key_other\napp_other\nins_other"))} {
		denied := request("/server/v1/installations?"+query, raw, nil)
		if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), "VALIDATION_FAILED") {
			t.Fatalf("invalid pagination %q = %d %s", query, denied.Code, denied.Body.String())
		}
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET restrict_to = jsonb_build_array(jsonb_build_object('space_id', $1::text, 'include_descendants', true)) WHERE name = 'server-test'`, customerSpaceID); err != nil {
		t.Fatal(err)
	}
	// Continuing an old page still uses the key's new restriction, not the cursor's old visibility.
	continued := readDiscoveryInstallations(t, request("/server/v1/installations?cursor="+url.QueryEscape(firstCursor), raw, nil))
	for _, installation := range continued.Body.Data {
		if installation.SpaceID != customerSpaceID {
			t.Fatal("old cursor retained visibility after restriction narrowing")
		}
	}
	current := readDiscoveryInstallations(t, request("/server/v1/installations", raw, nil))
	if len(current.Body.Data) != 1 || current.Body.Data[0].SpaceID != customerSpaceID || current.Body.Data[0].Scope != "space_tree" {
		t.Fatalf("tree installation roots = %+v", current.Body)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE spaces SET status = 'suspended' WHERE id = $1`, customerSpaceID); err != nil {
		t.Fatal(err)
	}
	empty := request("/server/v1/installations", raw, nil)
	if readDiscoveryInstallations(t, empty).Body.NextCursor != "" || !strings.Contains(empty.Body.String(), `"data":[]`) {
		t.Fatalf("inactive Space discovery = %s", empty.Body.String())
	}
}

func TestServerDiscoveryRechecksInstallationAndCredentialLifecycle(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, raw, _ := newServerFixture(t)
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	request := discoveryHTTP(t, &API{Applications: apps})
	baseline := readDiscoveryInstallations(t, request("/server/v1/installations", raw, nil))
	if len(baseline.Body.Data) != 1 {
		t.Fatalf("baseline installations = %+v", baseline.Body)
	}
	installation := baseline.Body.Data[0]
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'suspended' WHERE id = $1`, installation.MemberID); err != nil {
		t.Fatal(err)
	}
	if page := readDiscoveryInstallations(t, request("/server/v1/installations", raw, nil)); len(page.Body.Data) != 0 {
		t.Fatal("inactive installation member remained visible")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE members SET status = 'active' WHERE id = $1`, installation.MemberID); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"suspend", "resume", "uninstall"} {
		if _, err := apps.ChangeInstallationStatus(ctx, actor.ID, spaceID, installation.ID, action); err != nil {
			t.Fatal(err)
		}
		page := readDiscoveryInstallations(t, request("/server/v1/installations", raw, nil))
		want := 0
		if action == "resume" {
			want = 1
		}
		if len(page.Body.Data) != want {
			t.Fatalf("%s installation returned %d records, want %d", action, len(page.Body.Data), want)
		}
		if identity := request("/server/v1/key", raw, nil); identity.Code != http.StatusOK {
			t.Fatalf("installation lifecycle prevented key self-inspection: %d", identity.Code)
		}
	}
	authenticated, err := apps.AuthenticateKey(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	key, rotated, err := apps.RotateManagedKey(ctx, actor.ID, "app_server_test", authenticated.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/server/v1/key", "/server/v1/installations"} {
		for _, credential := range []string{raw, rotated.Value()} {
			if response := request(path, credential, nil); response.Code != http.StatusOK {
				t.Fatalf("rotation grace rejected discovery = %d %s", response.Code, response.Body.String())
			}
		}
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_key_grace_secrets SET valid_until = now() - interval '1 second' WHERE key_id = $1`, key.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/server/v1/key", "/server/v1/installations"} {
		if response := request(path, raw, nil); response.Code != http.StatusUnauthorized {
			t.Fatalf("old key remained valid after rotation grace: %d", response.Code)
		}
	}
	raw = rotated.Value()
	for _, path := range []string{"/server/v1/key", "/server/v1/installations"} {
		for _, credential := range []string{"", "ply_ag_invalid", "ply_ops_invalid", "invalid.jwt.token"} {
			denied := request(path, credential, nil)
			if denied.Code != http.StatusUnauthorized {
				t.Fatalf("wrong-plane credential on %s returned %d", path, denied.Code)
			}
		}
		if denied := request(path, raw, map[string]string{"Origin": "https://saas.example"}); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "BROWSER_ORIGIN_REJECTED") {
			t.Fatalf("browser origin = %d %s", denied.Code, denied.Body.String())
		}
	}
	for _, change := range []struct {
		name string
		sql  string
	}{
		{"revoked", `UPDATE api_keys SET revoked_at = now() WHERE name = 'server-test'`},
		{"expired", `UPDATE api_keys SET revoked_at = NULL, expires_at = now() - interval '1 second' WHERE name = 'server-test'`},
		{"application suspended", `UPDATE api_keys SET expires_at = now() + interval '1 hour'; UPDATE applications SET status = 'suspended' WHERE id = 'app_server_test'`},
		{"review withdrawn", `UPDATE applications SET status = 'active', visibility = 'public', review_status = 'pending' WHERE id = 'app_server_test'`},
		{"IP excluded", `UPDATE applications SET review_status = 'approved' WHERE id = 'app_server_test'; UPDATE api_keys SET allowed_ip_cidrs = '["198.51.100.0/24"]'::jsonb`},
	} {
		if _, err := st.Pool.Exec(ctx, change.sql); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/server/v1/key", "/server/v1/installations"} {
			denied := request(path, raw, map[string]string{"X-Forwarded-For": "198.51.100.7"})
			if denied.Code != http.StatusUnauthorized {
				t.Fatalf("%s on %s = %d %s", change.name, path, denied.Code, denied.Body.String())
			}
		}
	}
	st.Close()
	for _, path := range []string{"/server/v1/key", "/server/v1/installations"} {
		failed := request(path, raw, nil)
		if failed.Code != http.StatusServiceUnavailable || !strings.Contains(failed.Body.String(), "UNAVAILABLE") || strings.Contains(failed.Body.String(), "closed pool") {
			t.Fatalf("storage failure = %d %s", failed.Code, failed.Body.String())
		}
	}
}

func discoveryHTTP(t *testing.T, api *API) func(string, string, map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("server discovery test", "1.0.0")))
	handler := route.Middleware(route.Server, mux)
	return func(path, credential string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		for _, sensitive := range []string{"secret_hash", "client_secret", "password_hash", ".jwt.", "ply_ag_", "ply_ops_"} {
			if strings.Contains(response.Body.String(), sensitive) {
				t.Fatal("discovery response contains credential material")
			}
		}
		if credential != "" && strings.Contains(response.Body.String(), credential) {
			t.Fatal("discovery response contains the supplied credential")
		}
		if response.Code == http.StatusOK && response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("discovery response is cacheable")
		}
		return response
	}
}

func readDiscoveryInstallations(t *testing.T, response *httptest.ResponseRecorder) keyInstallationsOutput {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("installation discovery = %d %s", response.Code, response.Body.String())
	}
	var out keyInstallationsOutput
	if err := json.Unmarshal(response.Body.Bytes(), &out.Body); err != nil {
		t.Fatal(err)
	}
	return out
}
