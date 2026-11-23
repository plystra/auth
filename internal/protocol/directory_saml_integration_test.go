package protocol

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
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
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.Data.User.ID != f.userID || result.Data.User.Email != "directory-user@example.test" || result.Data.Tokens == nil {
				t.Fatalf("SAML did not reuse the directory identity: %v", err)
			}
			var authenticatedAt time.Time
			if err := f.st.Pool.QueryRow(ctx, "SELECT sso_auth_time FROM sessions WHERE id=$1", result.Data.Tokens.SessionID).Scan(&authenticatedAt); err != nil ||
				authenticatedAt.UTC().Format(time.RFC3339) != samlTestAuthenticationTime {
				t.Fatalf("session authentication time = %v, want %s: %v", authenticatedAt, samlTestAuthenticationTime, err)
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

func TestSAMLCallbackRollsBackWhenSigningCertificateExpiresDuringLogin(t *testing.T) {
	t.Run("single certificate", func(t *testing.T) { checkSAMLExpiryDuringLogin(t, false, false) })
	t.Run("implicit signer expires with same-key renewal", func(t *testing.T) { checkSAMLExpiryDuringLogin(t, true, false) })
	t.Run("active signer with expired predecessor", func(t *testing.T) { checkSAMLExpiryDuringLogin(t, true, true) })
}

func checkSAMLExpiryDuringLogin(t *testing.T, overlap, signWithReplacement bool) {
	t.Helper()
	f := newJITMappingFixture(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	f.svc.Issuer = "https://auth.test"
	notAfter := time.Now().Add(8 * time.Second).Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	metadata, signing := samlTestIssuerWithKey(t, key, time.Now().Add(-time.Minute), notAfter)
	if overlap {
		nextMetadata, replacement := samlTestIssuerWithKey(t, key, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		metadata = appendSAMLTestKey(t, metadata, nextMetadata, "signing")
		if signWithReplacement {
			signing = replacement
		}
	}
	actor := authorization.WithHumanActor(ctx, f.owner, "usr_sso_http_owner")
	connection, err := f.svc.CreateConnection(actor, f.owner, f.space, enterprise.ConnectionInput{
		Name: "Expiring IdP", Provider: "saml", SAMLMetadata: metadata,
		RedirectURI: "https://auth.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	var mux http.ServeMux
	(HTTP{Enterprise: f.svc}).Register(&mux)
	req := samlLoginRequest(t, ctx, &mux, connection, f.svc.Issuer, signing, overlap && !signWithReplacement)
	before := f.counts(t)
	gate, err := f.st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if err := f.st.InTx(gate.Context(ctx), func(q *db.Queries) error {
		_, err := q.LockSSOConnection(ctx, db.LockSSOConnectionParams{ID: connection.ID})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		done <- w
	}()
	for {
		var waiting bool
		if err := f.st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%LockSSOConnection%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case w := <-done:
			t.Fatalf("callback finished before the login lock: status=%d", w.Code)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if wait := time.Until(notAfter); wait > 0 {
		time.Sleep(wait + time.Millisecond)
	} else {
		t.Fatal("certificate expired before the verified callback reached its login lock")
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	w := <-done
	if signWithReplacement {
		requireSAMLLogin(t, w)
		// Once it is the sole active signer the successor can omit KeyInfo.
		after := httptest.NewRecorder()
		mux.ServeHTTP(after, samlLoginRequest(t, ctx, &mux, connection, f.svc.Issuer, signing, true))
		requireSAMLLogin(t, after)
		return
	}
	var refused struct{ Error struct{ Code string } }
	if w.Code != http.StatusServiceUnavailable || json.Unmarshal(w.Body.Bytes(), &refused) != nil || refused.Error.Code != "temporarily_unavailable" {
		t.Fatalf("callback after certificate expiry: status=%d code=%q", w.Code, refused.Error.Code)
	}
	if after := f.counts(t); after != before {
		t.Fatalf("expired callback changed state, identity, grants, audit or sessions: before=%v after=%v", before, after)
	}
}

func TestSAMLMetadataSigningOverlapAuthenticatesEitherIdPKey(t *testing.T) {
	f := newJITMappingFixture(t, false)
	ctx := t.Context()
	f.svc.Issuer = "https://auth.test"
	metadata, predecessor := newSAMLTestIssuer(t)
	next, successor := newSAMLTestIssuer(t)
	encryption, encryptionSigner := newSAMLTestIssuer(t)
	expired, expiredSigner := newSAMLTestIssuerUntil(t, time.Now().Add(-time.Second))
	upcoming, futureSigner := newSAMLTestIssuerWithWindow(t, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
	metadata = appendSAMLTestKey(t, metadata, next, "")
	metadata = appendSAMLTestKey(t, metadata, expired, "signing")
	metadata = appendSAMLTestKey(t, metadata, upcoming, "signing")
	metadata = appendSAMLTestKey(t, metadata, encryption, "encryption")
	// A certificate can also appear after the signing leaf in an X509Data chain.
	document := etree.NewDocument()
	if err := document.ReadFromString(metadata); err != nil {
		t.Fatal(err)
	}
	x509Data := document.Root().FindElement("./IDPSSODescriptor/KeyDescriptor/KeyInfo/X509Data")
	chainCert := document.Root().FindElement("./IDPSSODescriptor/KeyDescriptor[@use='encryption']/KeyInfo/X509Data/X509Certificate")
	x509Data.AddChild(chainCert.Copy())
	metadata, err := document.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	actor := authorization.WithHumanActor(ctx, f.owner, "usr_sso_http_owner")
	connection, err := f.svc.CreateConnection(actor, f.owner, f.space, enterprise.ConnectionInput{
		Name: "IdP signing rollover", Provider: "saml", SAMLMetadata: metadata,
		RedirectURI: "https://auth.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	var mux http.ServeMux
	(HTTP{Enterprise: f.svc}).Register(&mux)
	for _, tc := range []struct {
		name                 string
		signing              *dsig.SigningContext
		omitKeyInfo, allowed bool
	}{
		{"predecessor", predecessor, false, true},
		{"successor", successor, false, true},
		{"predecessor without KeyInfo", predecessor, true, true},
		{"successor without KeyInfo", successor, true, true},
		{"expired predecessor", expiredSigner, false, false},
		{"expired predecessor without KeyInfo", expiredSigner, true, false},
		{"before validity window", futureSigner, false, false},
		{"encryption only", encryptionSigner, false, false},
		{"encryption only without KeyInfo", encryptionSigner, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := samlLoginRequest(t, ctx, &mux, connection, f.svc.Issuer, tc.signing, tc.omitKeyInfo)
			before := f.counts(t)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if tc.allowed {
				requireSAMLLogin(t, w)
				return
			}
			var out struct{ Error struct{ Code string } }
			if w.Code != http.StatusBadRequest || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Error.Code != "invalid_grant" || f.counts(t) != before {
				t.Fatalf("unavailable signing key: status=%d code=%q", w.Code, out.Error.Code)
			}
		})
	}
	t.Run("explicit KeyInfo with more than four active signers", func(t *testing.T) {
		for range 3 {
			extra, _ := newSAMLTestIssuer(t)
			metadata = appendSAMLTestKey(t, metadata, extra, "signing")
		}
		large, err := f.svc.CreateConnection(actor, f.owner, f.space, enterprise.ConnectionInput{
			Name: "IdP with multiple active signing keys", Provider: "saml", SAMLMetadata: metadata,
			RedirectURI: "https://auth.test/v1/sso/{connection_id}/callback",
		})
		if err != nil {
			t.Fatal(err)
		}
		request := samlLoginRequest(t, ctx, &mux, large, f.svc.Issuer, successor, true)
		before := f.counts(t)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || f.counts(t) != before {
			t.Fatalf("omitted KeyInfo exceeded the verification budget: status=%d", response.Code)
		}
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, samlLoginRequest(t, ctx, &mux, large, f.svc.Issuer, successor, false))
		requireSAMLLogin(t, response)
	})
}

func samlLoginRequest(t *testing.T, ctx context.Context, mux *http.ServeMux, connection enterprise.Connection, issuer string, signer *dsig.SigningContext, omitKeyInfo bool) *http.Request {
	t.Helper()
	path := "/v1/sso/" + connection.ID
	start := httptest.NewRecorder()
	mux.ServeHTTP(start, httptest.NewRequestWithContext(ctx, http.MethodGet, path+"/start", nil))
	var result struct{ Data enterprise.StartResult }
	if start.Code != http.StatusOK || json.Unmarshal(start.Body.Bytes(), &result) != nil {
		t.Fatalf("SSO start status=%d", start.Code)
	}
	redirect, err := url.Parse(result.Data.AuthorizationURL)
	if err != nil || result.Data.State == "" || redirect.Query().Get("RelayState") != result.Data.State {
		t.Fatal("SSO start did not return a bound redirect")
	}
	raw, err := base64.StdEncoding.DecodeString(redirect.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	reader := flate.NewReader(bytes.NewReader(raw))
	defer func() { _ = reader.Close() }()
	var authRequest struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		ID      string   `xml:"ID,attr"`
	}
	if err := xml.NewDecoder(reader).Decode(&authRequest); err != nil || authRequest.ID == "" {
		t.Fatalf("invalid AuthnRequest in the redirect: %v", err)
	}
	payload := signedSAMLTestResponseForAudience(t, signer, connection.RedirectURI, issuer+"/saml/"+connection.ID, authRequest.ID, "rollover-user", nil, false)
	if omitKeyInfo {
		payload = samlTestWithoutKeyInfo(t, payload)
	}
	form := url.Values{"RelayState": {result.Data.State}, "SAMLResponse": {payload}}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path+"/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func samlTestWithoutKeyInfo(t *testing.T, response string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err := document.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	signature := document.Root().FindElement("./Signature")
	signature.RemoveChild(signature.FindElement("./KeyInfo"))
	raw, err = document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func requireSAMLLogin(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var out struct{ Data account.AuthResult }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Data.User.ID == "" || out.Data.Tokens == nil || out.Data.Tokens.SessionID == "" {
		t.Fatalf("SAML login did not return a session: status=%d", w.Code)
	}
}

func appendSAMLTestKey(t *testing.T, metadata, additional, use string) string {
	t.Helper()
	document, other := etree.NewDocument(), etree.NewDocument()
	if err := document.ReadFromString(metadata); err != nil {
		t.Fatal(err)
	}
	if err := other.ReadFromString(additional); err != nil {
		t.Fatal(err)
	}
	key := other.Root().FindElement("./IDPSSODescriptor/KeyDescriptor").Copy()
	key.RemoveAttr("use")
	if use != "" {
		key.CreateAttr("use", use)
	}
	idp := document.Root().FindElement("./IDPSSODescriptor")
	idp.InsertChildAt(idp.FindElement("./SingleSignOnService").Index(), key)
	encoded, err := document.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func newSAMLTestIssuer(t *testing.T) (string, *dsig.SigningContext) {
	t.Helper()
	return newSAMLTestIssuerUntil(t, time.Now().Add(time.Hour))
}

func newSAMLTestIssuerUntil(t *testing.T, notAfter time.Time) (string, *dsig.SigningContext) {
	t.Helper()
	return newSAMLTestIssuerWithWindow(t, time.Now().Add(-time.Minute), notAfter)
}

func newSAMLTestIssuerWithWindow(t *testing.T, notBefore, notAfter time.Time) (string, *dsig.SigningContext) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return samlTestIssuerWithKey(t, key, notBefore, notAfter)
}

func samlTestIssuerWithKey(t *testing.T, key *rsa.PrivateKey, notBefore, notAfter time.Time) (string, *dsig.SigningContext) {
	t.Helper()
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "directory-idp"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
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

const samlTestAuthenticationTime = "2025-01-01T00:00:00Z"

func signedSAMLTestResponse(t *testing.T, signing *dsig.SigningContext, connection enterprise.Connection, requestID, subject string, attributes []samlTestAttribute, tamper bool) string {
	t.Helper()
	return signedSAMLTestResponseForAudience(t, signing, connection.RedirectURI, "https://auth.test/saml/"+connection.ID, requestID, subject, attributes, tamper)
}

func signedSAMLTestResponseForAudience(t *testing.T, signing *dsig.SigningContext, recipient, audience, requestID, subject string, attributes []samlTestAttribute, tamper bool) string {
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
		<saml:AuthnStatement AuthnInstant="%s"><saml:AuthnContext>
		<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
		</saml:AuthnContext></saml:AuthnStatement>
		<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>different-saml-email@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
		</saml:Assertion></samlp:Response>`,
		now.Format(time.RFC3339), recipient, requestID, now.Format(time.RFC3339), recipient, requestID,
		now.Add(time.Minute).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339),
		audience, samlTestAuthenticationTime)
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
