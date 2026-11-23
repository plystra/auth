package enterprise

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/store"
)

func TestSAMLConnectionParsesMetadataBuildsBoundRequestAndRejectsInvalidResponse(t *testing.T) {
	ctx := context.Background()
	database, err := enterpriseDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status) VALUES ('usr_saml_owner', 'saml-owner@example.test', 'saml-owner@example.test', 'test-password-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authorizer := &authorization.Service{Store: st}
	space, owner, err := authorizer.CreateSpace(ctx, "usr_saml_owner", "SAML Space", "saml-space")
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	metadata := testSAMLMetadata(t, key)
	if _, err := parseSAMLMetadata(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + metadata + `</EntitiesDescriptor>`); err != nil {
		t.Fatalf("SAML EntitiesDescriptor metadata was rejected: %v", err)
	}
	service := &Service{Store: st, Authorization: authorizer, DataKey: secret.New(strings.Repeat("s", 32)), Issuer: "https://auth.example.test"}
	requestCtx := authorization.WithHumanActor(ctx, owner.ID, "usr_saml_owner")
	connection, err := service.CreateConnection(requestCtx, owner.ID, space.ID, ConnectionInput{
		Name: "Acme SAML", Provider: "saml", SAMLMetadata: metadata,
		RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if connection.Provider != "saml" || connection.ClientID == "" || connection.Issuer != "https://idp.example.test/entity" {
		t.Fatalf("SAML connection = %+v", connection)
	}
	start, err := service.Start(ctx, connection.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if start.State == "" || start.AuthorizationMethod != "GET" || parsed.Query().Get("SAMLRequest") == "" || parsed.Query().Get("RelayState") != start.State {
		t.Fatalf("SAML start result = %+v", start)
	}
	if _, err := service.Callback(ctx, CallbackInput{ConnectionID: connection.ID, State: start.State, SAMLResponse: "not-base64"}); err == nil {
		t.Fatal("invalid SAML response was accepted")
	}
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT client_secret_ciphertext FROM sso_connections WHERE id = $1`, connection.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != nil {
		t.Fatal("SAML connection stored a client secret")
	}
}

func testSAMLMetadata(t testing.TB, key *rsa.PrivateKey) string {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-idp"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test/entity"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + encoded + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor></EntityDescriptor>`
}
