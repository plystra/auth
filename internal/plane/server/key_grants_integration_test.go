package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/route"
)

func TestServerKeyGrantReplacementIsImmediateAcrossInstancesAndGraceSecrets(t *testing.T) {
	ctx := context.Background()
	st, authz, actor, spaceID, original, sessions := newServerFixture(t)
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	var keyID string
	if err := st.Pool.QueryRow(ctx, `SELECT id FROM api_keys WHERE application_id = 'app_server_test' AND name = 'server-test'`).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	_, rotated, err := apps.RotateManagedKey(ctx, actor.ID, "app_server_test", keyID)
	if err != nil {
		t.Fatal(err)
	}
	var handlers []http.Handler
	for range 2 {
		independent := &authorization.Service{Store: st}
		api := &API{Applications: &application.Service{Store: st, HMACKeys: apps.HMACKeys}, Authorization: independent, Sessions: sessions}
		mux := http.NewServeMux()
		api.Register(humago.New(mux, route.HumaConfig("key grants test", "1.0.0")))
		handlers = append(handlers, route.Middleware(route.Server, mux))
	}
	check := func(want int, code string) {
		t.Helper()
		for _, handler := range handlers {
			for _, secret := range []string{original, rotated.Value()} {
				body := fmt.Sprintf(`{"subject":{"member_id":%q},"action":"self:read","resource":{"type":"member","id":%q,"space_id":%q}}`, actor.ID, actor.ID, spaceID)
				request := httptest.NewRequest(http.MethodPost, "/server/v1/authz/check", strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+secret)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != want || !strings.Contains(response.Body.String(), code) {
					t.Fatalf("key authority status=%d expected=%d code=%s", response.Code, want, code)
				}
			}
		}
	}
	check(http.StatusOK, `"decision":"allow"`)
	if _, err := apps.UpdateManagedKeyGrants(ctx, actor.ID, "app_server_test", keyID, []string{"auth.tokens:introspect"}); err != nil {
		t.Fatal(err)
	}
	check(http.StatusForbidden, "PERMISSION_DENIED")
	if _, err := apps.UpdateManagedKeyGrants(ctx, actor.ID, "app_server_test", keyID, []string{"auth.authz:check", "auth.tokens:introspect"}); err != nil {
		t.Fatal(err)
	}
	check(http.StatusOK, `"decision":"allow"`)
	if _, err := st.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now()
		WHERE grantee_member_id = (SELECT member_id FROM application_installations WHERE application_id = 'app_server_test')`); err != nil {
		t.Fatal(err)
	}
	check(http.StatusOK, "NO_MATCHING_PERMISSION")
}
