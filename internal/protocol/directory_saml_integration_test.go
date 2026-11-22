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
	signing, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		values []string
		tamper bool
		want   int
	}{
		{"valid", []string{"Stable-Object-1"}, false, http.StatusOK},
		{"multiple_values", []string{"Stable-Object-1", "Other"}, false, http.StatusBadRequest},
		{"missing", nil, false, http.StatusBadRequest},
		{"case_mismatch", []string{"stable-object-1"}, false, http.StatusBadRequest},
		{"tampered", []string{"Stable-Object-1"}, true, http.StatusBadRequest},
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
			now := time.Now().UTC()
			xml := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">
				<saml:Issuer>https://directory-idp.test/entity</saml:Issuer>
				<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
				<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="%s">
				<saml:Issuer>https://directory-idp.test/entity</saml:Issuer><saml:Subject>
				<saml:NameID>saml-directory-subject</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
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
			statement := doc.Root().FindElement("./Assertion/AttributeStatement")
			for _, value := range tc.values {
				// Duplicate attributes must be treated as multiple values too.
				attribute := statement.CreateElement("saml:Attribute")
				attribute.CreateAttr("Name", "employee_id")
				attribute.CreateElement("saml:AttributeValue").SetText(value)
			}
			signed, err := signing.SignEnveloped(doc.Root())
			if err != nil {
				t.Fatal(err)
			}
			doc.SetRoot(signed)
			if tc.tamper {
				doc.Root().FindElement("./Assertion/Subject/NameID").SetText("tampered-subject")
			}
			encoded, err := doc.WriteToBytes()
			if err != nil {
				t.Fatal(err)
			}
			body := url.Values{"RelayState": {start.State}, "SAMLResponse": {base64.StdEncoding.EncodeToString(encoded)}}
			request := httptest.NewRequest("POST", "/v1/sso/"+connection.ID+"/callback", strings.NewReader(body.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			f.mux.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("SAML callback = %d, want %d: %s", response.Code, tc.want, response.Body.String())
			}
			if tc.want == http.StatusOK {
				var result struct{ Data account.AuthResult }
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Data.User.ID != f.userID || result.Data.User.Email != "directory-user@example.test" {
					t.Fatalf("SAML did not reuse the directory identity: %v", err)
				}
			}
		})
	}
}
