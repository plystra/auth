package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
)

func TestSSOGrantsRolesOnlyFromConfiguredGroupSource(t *testing.T) {
	const group = "engineering"
	const custom = "urn:example:teams"
	cases := []struct {
		name, provider, claim string
		oidc                  map[string]any
		saml                  []samlTestAttribute
		wantGrant             bool
	}{
		{name: "OIDC default", provider: "oidc", oidc: map[string]any{"groups": []string{group}}, wantGrant: true},
		{name: "OIDC custom", provider: "oidc", claim: custom, oidc: map[string]any{"groups": 42, custom: []string{group}}, wantGrant: true},
		{name: "OIDC missing custom", provider: "oidc", claim: custom, oidc: map[string]any{"groups": []string{group}}},
		{name: "SAML default", provider: "saml", saml: []samlTestAttribute{{name: "groups", value: group}}, wantGrant: true},
		{name: "SAML custom", provider: "saml", claim: custom, saml: []samlTestAttribute{{name: custom, value: group}}, wantGrant: true},
		{name: "SAML missing custom", provider: "saml", claim: custom, saml: []samlTestAttribute{
			{name: "groups", friendlyName: custom, value: group}, {name: "memberOf", value: group},
		}},
	}
	metadata, signing := newSAMLTestIssuer(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, _, svc, owner, spaceID, provider := newSSOHTTPFixture(t)
			svc.Issuer = "https://auth.test"
			const roleID = "rol_engineering"
			if _, err := st.Pool.Exec(ctx, "INSERT INTO roles (id, space_id, name, managed) VALUES ($1, $2, 'Engineering', false)", roleID, spaceID); err != nil {
				t.Fatal(err)
			}
			input := enterprise.ConnectionInput{
				Name: "Workforce", Provider: tc.provider, RedirectURI: svc.Issuer + "/v1/sso/{connection_id}/callback",
				GroupsClaim: tc.claim, RoleMappings: map[string]string{group: roleID},
			}
			if tc.provider == "saml" {
				input.SAMLMetadata = metadata
			} else {
				input.Issuer, input.ClientID, input.ClientSecret = provider.issuer, "mapping-client", "test-secret"
			}
			actor := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
			connection, err := svc.CreateConnection(actor, owner.ID, spaceID, input)
			if err != nil {
				t.Fatal(err)
			}
			start, err := svc.Start(ctx, connection.ID, "")
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			(HTTP{Enterprise: svc}).Register(mux)
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)
			code := "mapping-code"
			if tc.provider == "saml" {
				var requestID string
				if err := st.Pool.QueryRow(ctx, "SELECT request_id FROM sso_states WHERE connection_id=$1", connection.ID).Scan(&requestID); err != nil {
					t.Fatal(err)
				}
				code = signedSAMLTestResponse(t, signing, connection, requestID, "saml-subject", tc.saml, false)
			} else {
				authURL, err := url.Parse(start.AuthorizationURL)
				if err != nil {
					t.Fatal(err)
				}
				provider.addCode(code, oidcTestCode{nonce: authURL.Query().Get("nonce"),
					subject: "oidc-subject", email: "employee@example.test", emailVerified: true, extra: tc.oidc})
			}
			body, err := json.Marshal(map[string]string{"state": start.State, "code": code, "redirect_uri": connection.RedirectURI})
			if err != nil {
				t.Fatal(err)
			}
			response, err := server.Client().Post(server.URL+"/v1/sso/"+connection.ID+"/callback", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("callback returned HTTP %d", response.StatusCode)
			}
			var result struct{ Data account.AuthResult }
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			var hasDefault, hasMapped bool
			err = st.Pool.QueryRow(ctx, `SELECT bool_or(r.name='member'), bool_or(r.id=$1)
				FROM authorization_grants g JOIN roles r ON g.role_id=r.id
				JOIN user_members b ON b.member_id=g.grantee_member_id
				WHERE g.space_id=$2 AND b.user_id=$3 AND g.granted_by=$4`, roleID, spaceID, result.Data.User.ID, connection.ID).Scan(&hasDefault, &hasMapped)
			if err != nil {
				t.Fatal(err)
			}
			if !hasDefault || hasMapped != tc.wantGrant {
				t.Errorf("default member grant = %t, mapped grant = %t (want %t)", hasDefault, hasMapped, tc.wantGrant)
			}
		})
	}
}
