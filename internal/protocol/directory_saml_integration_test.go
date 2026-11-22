package protocol

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestDirectorySAMLSSOUsesVerifiedStableAttributeAndRejectsAmbiguity(t *testing.T) {
	f := newDirectorySSOFixture(t, "sub")
	ctx := context.Background()
	metadata, signing := newSAMLTestIssuer(t)
	f.svc.Issuer = "https://auth.test"
	actor := authorization.WithHumanActor(ctx, f.owner.ID, "usr_sso_http_owner")
	connection, err := f.svc.CreateConnection(actor, f.owner.ID, f.spaceID, enterprise.ConnectionInput{
		Name: "Directory SAML", Provider: "saml", SAMLMetadata: metadata, RedirectURI: "https://auth.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := "employee_id"
	if _, err := f.svc.UpdateDirectory(actor, f.owner.ID, f.spaceID, f.directory.ID,
		enterprise.DirectoryUpdate{SSOConnectionID: &connection.ID, SSOIdentityClaim: &claim}, 1); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f.mux)
	t.Cleanup(server.Close)
	callback := func(t *testing.T, contentType, body string, want int) {
		t.Helper()
		response, err := server.Client().Post(server.URL+"/v1/sso/"+connection.ID+"/callback", contentType, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != want {
			t.Fatalf("SAML callback status = %d, want %d", response.StatusCode, want)
		}
		if want == http.StatusOK {
			var result struct{ Data account.AuthResult }
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.Data.User.ID != f.userID || result.Data.User.Email != "directory-user@example.test" {
				t.Fatalf("SAML did not reuse the directory identity: %v", err)
			}
		} else {
			var result struct{ Error struct{ Code string } }
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.Error.Code != "invalid_grant" {
				t.Errorf("SAML error code = %q, want invalid_grant: %v", result.Error.Code, err)
			}
		}
	}
	for _, tc := range []struct {
		name        string
		values      []string
		tamper      bool
		want        int
		json        bool
		redirectURI string
	}{
		{name: "valid", values: []string{"Stable-Object-1"}, want: http.StatusOK},
		{name: "multiple_values", values: []string{"Stable-Object-1", "Other"}, want: http.StatusBadRequest},
		{name: "missing", want: http.StatusBadRequest},
		{name: "case_mismatch", values: []string{"stable-object-1"}, want: http.StatusBadRequest},
		{name: "tampered", values: []string{"Stable-Object-1"}, tamper: true, want: http.StatusBadRequest},
		{name: "json_valid", values: []string{"Stable-Object-1"}, json: true, redirectURI: connection.RedirectURI, want: http.StatusOK},
		{name: "json_invalid_signature", values: []string{"Stable-Object-1"}, tamper: true, json: true, redirectURI: connection.RedirectURI, want: http.StatusBadRequest},
		{name: "json_mismatched_redirect", values: []string{"Stable-Object-1"}, json: true, redirectURI: "https://other.example.test/callback", want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, err := f.svc.Start(ctx, connection.ID, "")
			if err != nil {
				t.Fatal(err)
			}
			var requestID string
			if err := f.st.Pool.QueryRow(ctx, "SELECT request_id FROM sso_states WHERE connection_id=$1 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1", connection.ID).Scan(&requestID); err != nil {
				t.Fatal(err)
			}
			var attributes []samlTestAttribute
			for _, value := range tc.values {
				attributes = append(attributes, samlTestAttribute{name: "employee_id", value: value})
			}
			samlResponse := signedSAMLTestResponse(t, signing, connection, requestID, "saml-directory-subject", attributes, tc.tamper)
			contentType := "application/x-www-form-urlencoded"
			body := url.Values{"RelayState": {start.State}, "SAMLResponse": {samlResponse}}.Encode()
			if tc.json {
				contentType = "application/json"
				data, err := json.Marshal(map[string]string{"state": start.State, "code": samlResponse, "redirect_uri": tc.redirectURI})
				if err != nil {
					t.Fatal(err)
				}
				body = string(data)
			}
			callback(t, contentType, body, tc.want)
			if tc.want == http.StatusOK {
				callback(t, contentType, body, http.StatusBadRequest)
			}
		})
	}
}

func newSAMLTestIssuer(t *testing.T) (string, *dsig.SigningContext) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "directory-idp"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	metadata := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://directory-idp.test/entity">
	<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing">
	<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(der) + `</X509Certificate></X509Data></KeyInfo>
	</KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://directory-idp.test/sso"/>
	</IDPSSODescriptor></EntityDescriptor>`
	signing, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	return metadata, signing
}

type samlTestAttribute struct {
	name, friendlyName, value string
}

func signedSAMLTestResponse(t *testing.T, signing *dsig.SigningContext, connection enterprise.Connection, requestID, subject string, attributes []samlTestAttribute, tamper bool) string {
	t.Helper()
	now := time.Now().UTC()
	xml := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">
		<saml:Issuer>https://directory-idp.test/entity</saml:Issuer>
		<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
		<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="%s">
		<saml:Issuer>https://directory-idp.test/entity</saml:Issuer><saml:Subject>
		<saml:NameID></saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
		<saml:SubjectConfirmationData Recipient="%s" InResponseTo="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject>
		<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>
		<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>different-saml-email@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
		</saml:Assertion></samlp:Response>`,
		now.Format(time.RFC3339), connection.RedirectURI, requestID, now.Format(time.RFC3339), connection.RedirectURI, requestID,
		now.Add(time.Minute).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339),
		"https://auth.test/saml/"+connection.ID)
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xml); err != nil {
		t.Fatal(err)
	}
	doc.Root().FindElement("./Assertion/Subject/NameID").SetText(subject)
	statement := doc.Root().FindElement("./Assertion/AttributeStatement")
	for _, value := range attributes {
		attribute := statement.CreateElement("saml:Attribute")
		attribute.CreateAttr("Name", value.name)
		if value.friendlyName != "" {
			attribute.CreateAttr("FriendlyName", value.friendlyName)
		}
		attribute.CreateElement("saml:AttributeValue").SetText(value.value)
	}
	signed, err := signing.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	doc.SetRoot(signed)
	if tamper {
		doc.Root().FindElement("./Assertion/Subject/NameID").SetText("tampered-subject")
	}
	encoded, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}
