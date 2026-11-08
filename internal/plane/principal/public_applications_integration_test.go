package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/route"
)

func TestPublicApplicationRegistrationHTTPStartsWithNoEffectiveManifest(t *testing.T) {
	ctx := context.Background()
	st, authz, publisher, publisherSpace, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, publisherSpace, publisher.ID, publisher.ID, "auth.applications:manage")
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Signer: signer, Applications: apps}).Register(
		humago.New(mux, route.HumaConfig("public application registration", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", publisher.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+publisherSpace+"/applications", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		r.Header.Set("Content-Type", "application/json")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	body := `{"name":"Billing","visibility":"public","manifest_permissions":["auth.authz:check"]}`
	if got := post(body); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatalf("public registration without step-up = %d %s", got.Code, got.Body.String())
	}
	seedStepUpProof(t, st, tokens.SessionID, "applications.register", map[string]any{
		"space_id": publisherSpace, "name": "Billing", "visibility": "public",
		"redirect_uris": []string(nil), "manifest_permissions": []string{"auth.authz:check"},
	})
	got := post(body)
	if got.Code != http.StatusOK {
		t.Fatalf("public registration = %d %s", got.Code, got.Body.String())
	}
	var result struct {
		Data application.PublishedApplication `json:"data"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data.Visibility != "public" || result.Data.ReviewStatus != "pending" || len(result.Data.ManifestPermissions) != 0 || len(result.Data.PendingManifestPermissions) != 1 {
		t.Fatalf("public registration state = %+v", result.Data)
	}
	if got := post(`{"name":"Billing","visibility":"unknown","manifest_permissions":["auth.authz:check"]}`); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid visibility = %d %s", got.Code, got.Body.String())
	}
}

func TestPublicApplicationNeedsApprovalBeforeCrossSpaceInstallation(t *testing.T) {
	ctx := context.Background()
	st, authz, publisher, publisherSpace, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, publisherSpace, publisher.ID, publisher.ID, "auth.applications:manage")
	apps := &application.Service{Store: st, Authorization: authz, StepUp: sessions,
		HMACKeys: [][]byte{[]byte(strings.Repeat("k", 32))}}
	registered, err := apps.Register(ctx, publisher.ID, application.RegisterInput{
		SpaceID: publisherSpace, Name: "Cross customer billing", Visibility: "public",
		ManifestPermissions: []string{"auth.authz:check", "auth.tokens:introspect"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if registered.Visibility != "public" || registered.ReviewStatus != "pending" || len(registered.ManifestPermissions) != 0 || len(registered.PendingManifestPermissions) != 2 {
		t.Fatalf("public application was active before review: %+v", registered)
	}
	if _, err := apps.OAuthClient(ctx, registered.ClientID); err == nil {
		t.Fatal("unapproved public application was accepted as an OAuth client")
	}
	customerSpace, customer, err := authz.CreateSpace(ctx, "usr_principal_actor", "Customer", "cross-customer")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, customerSpace.ID, customer.ID, customer.ID, "auth.applications:manage")
	if _, err := apps.InstallSpace(ctx, customer.ID, registered.ID, customerSpace.ID); err == nil {
		t.Fatal("unapproved public application installed in customer Space")
	} else {
		assertPrincipalError(t, err, "NOT_FOUND")
	}
	if _, _, err := apps.CreateManagedKey(ctx, publisher.ID, registered.ID, application.CreateManagedKeyInput{
		Name: "server", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
	}); err == nil {
		t.Fatal("unapproved public application issued a usable API key")
	}
	if _, err := st.Pool.Exec(ctx, `
		UPDATE applications SET manifest_permissions = '["auth.authz:check"]'::jsonb,
		allowed_scopes = '["auth.authz:check"]'::jsonb,
		pending_manifest_permissions = NULL, review_status = 'approved'
		WHERE id = $1
	`, registered.ID); err != nil {
		t.Fatal(err)
	}
	client, err := apps.OAuthClient(ctx, registered.ClientID)
	if err != nil || len(client.AllowedScopes) != 1 || client.AllowedScopes[0] != "auth.authz:check" {
		t.Fatalf("approved OAuth client scopes = %+v error = %v", client.AllowedScopes, err)
	}
	mux := http.NewServeMux()
	(&API{Authorization: authz, Sessions: sessions, Signer: signer, Applications: apps}).Register(
		humago.New(mux, route.HumaConfig("public customer installation", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	tokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", customer.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	seedStepUpProof(t, st, tokens.SessionID, "installations.create", map[string]any{
		"space_id": customerSpace.ID, "application_id": registered.ID, "scope": "space",
	})
	created := postInstallation(t, handler, customerSpace.ID, registered.ID, tokens.AccessToken)
	if created.Code != http.StatusOK || !strings.Contains(created.Body.String(), `"approved_permissions":["auth.authz:check"]`) {
		t.Fatalf("approved cross-customer installation = %d %s", created.Code, created.Body.String())
	}
	treeSpace, treeActor, err := authz.CreateSpace(ctx, "usr_principal_actor", "Tree customer", "tree-customer")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, treeSpace.ID, treeActor.ID, treeActor.ID, "auth.applications:manage")
	if _, err := apps.Install(ctx, treeActor.ID, registered.ID, treeSpace.ID, "space_tree"); err != nil {
		t.Fatalf("approved public tree installation: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug, parent_id)
		VALUES ('spc_public_tree_child', 'Tree child', 'public-tree-child', $1)`, treeSpace.ID); err != nil {
		t.Fatal(err)
	}
	key, raw, err := apps.CreateManagedKey(ctx, publisher.ID, registered.ID, application.CreateManagedKeyInput{
		Name: "server", Grants: []string{"auth.authz:check"}, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.ApplicationID != registered.ID {
		t.Fatalf("API key application = %s", key.ApplicationID)
	}
	authenticated, err := apps.AuthenticateKey(ctx, raw.Value())
	if err != nil {
		t.Fatal(err)
	}
	memberID, deny, err := apps.ResolveKeyInstallation(ctx, authenticated, customerSpace.ID)
	if err != nil || deny != "" || !strings.HasPrefix(memberID, "mem_") {
		t.Fatalf("customer key installation = member %q deny %q err %v", memberID, deny, err)
	}
	if treeMember, treeDeny, err := apps.ResolveKeyInstallation(ctx, authenticated, "spc_public_tree_child"); err != nil || treeDeny != "" || !strings.HasPrefix(treeMember, "mem_") {
		t.Fatalf("tree child key installation = member %q deny %q err %v", treeMember, treeDeny, err)
	}
}
