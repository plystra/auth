//go:build interop

package protocol

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/oauth2"
)

func TestKeycloakWorkforceSAMLUsesCurrentRoleMapping(t *testing.T) {
	ctx := t.Context()
	upstream := &http.Client{Timeout: 15 * time.Second}
	rp := newHumanRPWithWorkforce(t, false, upstream)
	adminPassword := oauth2.GenerateVerifier()
	issuer, transport := keycloakFixture(t, rp.host.URL+"/oidc/upstream", testcontainers.WithEnv(map[string]string{
		"KC_BOOTSTRAP_ADMIN_USERNAME": keycloakFixtureAdmin,
		"KC_BOOTSTRAP_ADMIN_PASSWORD": adminPassword,
	}))
	upstream.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)

	const adminID = "usr_human_rp"
	authz := rp.workforce.Authorization
	space, owner, err := authz.CreateSpace(ctx, adminID, "Workforce SAML Mapping", "workforce-saml-mapping")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_keycloak_saml_mapping',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	actor := authorization.WithHumanActor(ctx, owner.ID, adminID)
	role := func(name, permission string) string {
		t.Helper()
		value, err := authz.CreateRole(actor, owner.ID, space.ID, name, "", []string{permission})
		if err != nil {
			t.Fatal(err)
		}
		return value.ID
	}
	original := role("Original engineering", "auth.members:read")
	replacement := role("Current engineering", "auth.audit:read")
	connection, err := rp.workforce.CreateConnection(actor, owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Keycloak Workforce SAML", Provider: "saml",
		SAMLMetadata: fetchKeycloakSAMLMetadata(t, upstream, issuer),
		RedirectURI:  rp.host.URL + route.SAMLBrowserCallbackPrefix + "{connection_id}",
		RoleMappings: map[string]string{"engineering": original},
	})
	if err != nil {
		t.Fatal(err)
	}
	registerKeycloakSAMLConnection(t, rp, upstream, issuer, adminPassword, space.ID, connection)
	domain, err := rp.workforce.CreateDomain(actor, owner.ID, space.ID,
		enterprise.DomainInput{Domain: "workforce.example.test", ConnectionID: connection.ID, ForceSSO: true})
	if err != nil {
		t.Fatal(err)
	}
	rp.workforce.DNSResolver = employeeDomainResolver{domain.VerificationToken}
	if err := rp.workforce.VerifyDomain(actor, owner.ID, space.ID, domain.ID); err != nil {
		t.Fatal(err)
	}

	login := func(username string) string {
		t.Helper()
		browser := newOIDCBrowser(t, rp)
		verifier, state, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
		path := browser.beginFromAuthorization(t, verifier, state, nonce)
		email := username + "@workforce.example.test"
		identified, _ := browser.request(t, http.MethodPost, path+"/identify", map[string]string{"email": email, "method": "password"}, rp.host.URL, "", http.StatusOK)
		if identified.NextStep != "sso" || identified.SSOConnectionID != connection.ID {
			t.Fatal("employee was not routed to the configured SAML connection")
		}
		keycloakSAMLCallback(t, rp, transport, issuer, connection.RedirectURI, path, username, identified)
		loggedIn, _ := browser.request(t, http.MethodPost, path+"/sso/saml/complete", nil, rp.host.URL, "", http.StatusOK)
		if loggedIn.NextStep != "consent" || loggedIn.Email != email {
			t.Fatal("verified SAML identity did not reach relying party consent")
		}
		decision, _ := browser.request(t, http.MethodPost, path+"/decision", map[string]string{"decision": "approve"}, rp.host.URL, "", http.StatusOK)
		redirect, err := url.Parse(decision.RedirectTo)
		if err != nil || redirect.Scheme+"://"+redirect.Host+redirect.Path != rp.config.RedirectURL || redirect.Query().Get("state") != state {
			t.Fatal("Auth did not return to the registered relying party")
		}
		clientContext := oidc.ClientContext(ctx, rp.host.Client())
		token, err := rp.config.Exchange(clientContext, redirect.Query().Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			t.Fatal("relying party could not exchange the authorization code")
		}
		raw, _ := token.Extra("id_token").(string)
		identity, err := rp.provider.Verifier(&oidc.Config{ClientID: rp.config.ClientID}).Verify(clientContext, raw)
		if err != nil || identity.Nonce != nonce || identity.Subject == "" {
			t.Fatal("relying party could not verify the employee identity")
		}
		return identity.Subject
	}
	assertRole := func(user, want, excluded string) {
		t.Helper()
		var matched, rejected int
		err := rp.st.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE g.role_id=$3), count(*) FILTER (WHERE g.role_id=$4)
			FROM authorization_grants g JOIN user_members b ON b.member_id=g.grantee_member_id
			WHERE b.user_id=$1 AND b.status='active' AND b.revoked_at IS NULL AND g.space_id=$2 AND g.revoked_at IS NULL`,
			user, space.ID, want, excluded).Scan(&matched, &rejected)
		if err != nil || matched != 1 || rejected != 0 {
			t.Fatalf("expected one mapped role and no conflicting grant, got %d/%d: %v", matched, rejected, err)
		}
	}
	first := login("original")
	assertRole(first, original, replacement)

	rp.workforce.Sessions.Factors = &factor.Service{Store: rp.st, DataKey: secret.New(strings.Repeat("d", 32))}
	enrollment, err := rp.workforce.Sessions.Factors.BeginTOTP(ctx, adminID, "rp@example.test")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret.Value(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	client := employeeLifecycleClient{server: rp.host}
	const jsonType = "application/json"
	mappings := map[string]string{"engineering": replacement}
	client.send(t, http.MethodPost, "/v1/auth/step-up", rp.session.AccessToken, jsonType, "", map[string]any{
		"operation": enterprise.SSOConnectionUpdateOperation, "mfa_code": code,
		"request": enterprise.SSORoleMappingUpdateRequest(space.ID, connection.ID, connection.ETag(), mappings),
	}).requireStatus(t, http.StatusOK)
	updated := client.send(t, http.MethodPatch, "/v1/spaces/"+space.ID+"/sso-connections/"+connection.ID,
		rp.session.AccessToken, jsonType, connection.ETag(), map[string]any{"role_mappings": mappings})
	updated.requireStatus(t, http.StatusOK)
	if updated.etag == "" || updated.etag == connection.ETag() {
		t.Fatal("connection mapping update did not advance the version")
	}
	second := login("newcomer")
	if first == second || login("original") != first {
		t.Fatal("SAML login failed to preserve the distinct account bindings")
	}
	assertRole(second, replacement, original)
	assertRole(first, original, replacement)
}
