//go:build interop

package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/route"
	"golang.org/x/net/html"
)

const (
	keycloakFixtureAdmin       = "fixture-admin"
	keycloakSAMLDirectoryClaim = "employee_id"
)

func fetchKeycloakSAMLMetadata(t *testing.T, client *http.Client, issuer string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, issuer+"/protocol/saml/descriptor", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("fetch Keycloak SAML metadata failed")
	}
	defer func() { _ = res.Body.Close() }()
	const metadataLimit = 1 << 20
	body, err := io.ReadAll(io.LimitReader(res.Body, metadataLimit+1))
	if err != nil || len(body) == 0 || len(body) > metadataLimit || res.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak SAML metadata is unavailable or invalid: %d", res.StatusCode)
	}
	return string(body)
}

func registerKeycloakSAMLClient(t *testing.T, client *http.Client, issuer, password, entityID, callback string) {
	t.Helper()
	origin := strings.TrimSuffix(issuer, "/realms/"+keycloakRealm)
	form := url.Values{
		"client_id": {"admin-cli"}, "grant_type": {"password"},
		"username": {keycloakFixtureAdmin}, "password": {password},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("authenticate to the disposable Keycloak administration endpoint failed")
	}
	var credential struct {
		AccessToken string `json:"access_token"`
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 32<<10)).Decode(&credential)
	_ = res.Body.Close()
	if err != nil || credential.AccessToken == "" || res.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak fixture administrator authentication failed: %d", res.StatusCode)
	}

	mapper := func(name, kind string) map[string]any {
		return map[string]any{
			"name": name, "protocol": "saml", "protocolMapper": kind,
			"config": map[string]string{"user.attribute": name, "attribute.name": name, "attribute.nameformat": "Basic"},
		}
	}
	body, err := json.Marshal(map[string]any{
		"clientId": entityID, "protocol": "saml", "enabled": true, "adminUrl": callback,
		"redirectUris": []string{callback},
		"attributes": map[string]string{
			"saml_assertion_consumer_url_post": callback, "saml.force.post.binding": "true",
			"saml.client.signature": "false", "saml.server.signature": "true",
			"saml.assertion.signature": "true", "saml.signature.algorithm": "RSA_SHA256",
			"saml.authnstatement": "true", "saml_name_id_format": "persistent",
		},
		"protocolMappers": []map[string]any{
			mapper("email", "saml-user-property-mapper"),
			mapper(keycloakSAMLDirectoryClaim, "saml-user-attribute-mapper"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err = http.NewRequestWithContext(t.Context(), http.MethodPost, origin+"/admin/realms/"+keycloakRealm+"/clients", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential.AccessToken)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal("register the disposable Keycloak SAML client failed")
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("Keycloak rejected the fixture SAML client: %d", res.StatusCode)
	}
}

func keycloakSAMLCallback(t *testing.T, rp *humanRP, transport *http.Transport, issuer, callback, interaction string, identified interactionResponse) {
	t.Helper()
	target, err := url.Parse(identified.AuthorizationURL)
	if err != nil || identified.AuthorizationMethod != http.MethodGet ||
		target.Scheme+"://"+target.Host+target.EscapedPath() != issuer+"/protocol/saml" ||
		target.Query().Get("SAMLRequest") == "" || target.Query().Get("RelayState") == "" {
		t.Fatal("the interaction did not start the discovered Keycloak SAML endpoint")
	}
	login := submitKeycloakLogin(t, transport, target.String(), "original")
	page, err := html.Parse(io.LimitReader(login.Body, 128<<10))
	_ = login.Body.Close()
	if err != nil || login.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak did not return an HTML SAML callback: %d", login.StatusCode)
	}
	posted := keycloakSAMLForm(page, callback)
	if len(posted["SAMLResponse"]) != 1 || posted.Get("SAMLResponse") == "" ||
		len(posted["RelayState"]) != 1 || posted.Get("RelayState") != target.Query().Get("RelayState") {
		t.Fatal("Keycloak's POST was not bound to the exact ACS and original relay")
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, callback, strings.NewReader(posted.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", target.Scheme+"://"+target.Host)
	acs := &http.Client{Transport: rp.host.Client().Transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err := acs.Do(req)
	if err != nil {
		t.Fatal("POST the Keycloak form to the service provider failed")
	}
	defer func() { _ = res.Body.Close() }()
	redirect := "/oidc/upstream#interaction=" + strings.TrimPrefix(interaction, route.OIDCInteractionsPath+"/")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != redirect {
		t.Fatalf("the ACS did not resume its original interaction: %d", res.StatusCode)
	}
}

func keycloakSAMLForm(page *html.Node, callback string) url.Values {
	for form := range page.Descendants() {
		if form.Type != html.ElementNode || form.Data != "form" {
			continue
		}
		var action, method string
		for _, attr := range form.Attr {
			switch attr.Key {
			case "action":
				action = attr.Val
			case "method":
				method = attr.Val
			}
		}
		if action != callback || !strings.EqualFold(method, "POST") {
			continue
		}
		values := make(url.Values)
		for input := range form.Descendants() {
			if input.Type != html.ElementNode || input.Data != "input" {
				continue
			}
			var name, value string
			for _, attr := range input.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "value":
					value = attr.Val
				}
			}
			if name == "SAMLResponse" || name == "RelayState" {
				values.Add(name, value)
			}
		}
		return values
	}
	return nil
}
