package protocol

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/stepup"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestSAMLSigningMetadataUpdatesOnlineAndPreservesIdentity(t *testing.T) {
	rp := newConfiguredHumanRP(t, false, newOIDCTestProvider(t))
	ctx := t.Context()
	const operatorID = "usr_human_rp"
	space, owner, err := rp.workforce.Authorization.CreateSpace(ctx, operatorID, "SSO certificate rollover", "rollover")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.st.Pool.Exec(ctx, `INSERT INTO authorization_grants (id,space_id,permission_keys,grantee_member_id,scope,anchor_space_id,granted_by)
		VALUES ('grt_online_saml_manager',$1,'["auth.connections:manage"]',$2,'space',$1,$2)`, space.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	metadata, oldSigner := newSAMLTestIssuer(t)
	replacement, nextSigner := newSAMLTestIssuer(t)
	overlap := appendSAMLTestKey(t, metadata, replacement, "signing")
	connection, err := rp.workforce.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, operatorID), owner.ID, space.ID, enterprise.ConnectionInput{
		Name: "Workforce", Provider: "saml", SAMLMetadata: metadata, RedirectURI: rp.host.URL + "/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/spaces/" + space.ID + "/sso-connections/" + connection.ID
	prove := func(operation string, request map[string]string) {
		t.Helper()
		digest, err := stepup.DigestValue(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rp.st.Pool.Exec(ctx, `UPDATE sessions SET step_up_operation=$2, step_up_digest=$3,
			step_up_method='totp', step_up_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1`, rp.session.SessionID, operation, digest); err != nil {
			t.Fatal(err)
		}
	}
	admin := func(method, tag, metadataXML string, status int) (enterprise.Connection, string) {
		t.Helper()
		var body []byte
		if metadataXML != "" {
			body, _ = json.Marshal(map[string]string{"saml_metadata": metadataXML})
		}
		request, err := http.NewRequestWithContext(ctx, method, rp.host.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+rp.session.AccessToken)
		request.Header.Set("Content-Type", "application/json")
		if tag != "" {
			request.Header.Set("If-Match", tag)
		}
		response, err := rp.host.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		var result struct {
			Data  enterprise.ConnectionDetail
			Error struct{ Code string }
		}
		wire, err := io.ReadAll(response.Body)
		if err != nil || json.Unmarshal(wire, &result) != nil {
			t.Fatal("invalid SSO management response")
		}
		if response.StatusCode != status {
			t.Fatalf("%s returned %d (%s), want %d", method, response.StatusCode, result.Error.Code, status)
		}
		if bytes.Contains(wire, []byte("BEGIN CERTIFICATE")) || bytes.Contains(wire, []byte(`"saml_metadata"`)) {
			t.Fatal("SSO management disclosed signing metadata")
		}
		if method == http.MethodGet && status == http.StatusOK && result.Data.Status == "active" {
			var document types.EntityDescriptor
			err := xml.Unmarshal([]byte(result.Data.SAMLSPMetadata), &document)
			sp := document.SPSSODescriptor
			if err != nil || document.EntityID != rp.host.URL+"/saml/"+connection.ID || document.IDPSSODescriptor != nil ||
				sp == nil || sp.AuthnRequestsSigned || !sp.WantAssertionsSigned || sp.ProtocolSupportEnumeration != saml2.SAMLProtocolNamespace ||
				len(sp.KeyDescriptors) != 0 || len(sp.SingleLogoutServices) != 0 || len(sp.AssertionConsumerServices) != 1 ||
				sp.AssertionConsumerServices[0].Binding != saml2.BindingHttpPost || sp.AssertionConsumerServices[0].Location != connection.RedirectURI {
				t.Fatal("export did not match this connection's SP profile and exact ACS")
			}
		} else if result.Data.SAMLSPMetadata != "" {
			t.Fatal("the SP metadata must only be present on the protected detail read")
		}
		return result.Data.Connection, response.Header.Get("ETag")
	}
	var protocol http.ServeMux
	(HTTP{Enterprise: rp.workforce}).Register(&protocol)
	login := func(signer *dsig.SigningContext, omitKeyInfo bool, want int) account.AuthResult {
		t.Helper()
		started := samlLoginRequest(t, ctx, &protocol, connection, rp.host.URL, signer, omitKeyInfo)
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, rp.host.URL+started.URL.Path, started.Body)
		if err != nil {
			t.Fatal(err)
		}
		request.Header = started.Header.Clone()
		response, err := rp.host.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		var result struct {
			Data  account.AuthResult
			Error struct{ Code string }
		}
		if json.NewDecoder(response.Body).Decode(&result) != nil || response.StatusCode != want || want == http.StatusOK && result.Data.Tokens == nil {
			t.Fatalf("SAML callback returned %d (%s), want %d", response.StatusCode, result.Error.Code, want)
		}
		return result.Data
	}
	initial := login(oldSigner, false, http.StatusOK)
	prove("sso_connections.get", enterprise.ConnectionDetailRequest(space.ID, connection.ID))
	_, oldTag := admin(http.MethodGet, "", "", http.StatusOK)
	if oldTag != connection.ETag() || oldTag == "" {
		t.Fatal("management GET did not return the current ETag")
	}
	const op = enterprise.SSOConnectionUpdateOperation
	bind := func(tag, xml string) {
		prove(op, enterprise.SAMLMetadataUpdateRequest(space.ID, connection.ID, tag, xml))
	}
	admin(http.MethodPatch, "", overlap, http.StatusPreconditionFailed)
	admin(http.MethodPatch, oldTag, overlap, http.StatusForbidden)
	bind(oldTag, overlap)
	admin(http.MethodPatch, oldTag, replacement, http.StatusForbidden)
	drift := strings.Replace(replacement, "https://directory-idp.test/sso", "https://other.example.test/sso", 1)
	bind(oldTag, drift)
	admin(http.MethodPatch, oldTag, drift, http.StatusBadRequest)

	if _, err := rp.st.Pool.Exec(ctx, `CREATE FUNCTION reject_saml_metadata_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action='sso.connection.saml_metadata.update' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER reject_saml_metadata_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_saml_metadata_audit()`); err != nil {
		t.Fatal(err)
	}
	bind(oldTag, overlap)
	admin(http.MethodPatch, oldTag, overlap, http.StatusServiceUnavailable)
	if _, err := rp.st.Pool.Exec(ctx, `DROP TRIGGER reject_saml_metadata_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	updated, overlapTag := admin(http.MethodPatch, oldTag, overlap, http.StatusOK)
	if updated.ID != connection.ID || updated.Issuer != connection.Issuer || updated.RedirectURI != connection.RedirectURI || overlapTag == "" || overlapTag == oldTag {
		t.Fatal("updating signing keys changed the connection's identity or retained the old version")
	}
	if result := login(nextSigner, true, http.StatusOK); result.User.ID != initial.User.ID {
		t.Fatal("the replacement certificate changed the existing subject binding")
	}
	login(oldSigner, false, http.StatusOK)
	bind(oldTag, replacement)
	admin(http.MethodPatch, oldTag, replacement, http.StatusPreconditionFailed)
	bind(overlapTag, replacement)
	admin(http.MethodPatch, overlapTag, replacement, http.StatusOK)
	login(oldSigner, false, http.StatusBadRequest)
	login(nextSigner, false, http.StatusOK)
	if _, active, err := rp.workforce.Sessions.Introspect(ctx, initial.Tokens.AccessToken, security.DefaultApplicationAudience); !active || err != nil {
		t.Fatal("updating signing certificates interrupted an existing authenticated session")
	}
	var audited int
	if err := rp.st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='sso.connection.saml_metadata.update'
		AND resource_id=$1 AND member_id=$2 AND length(metadata->>'new_trust_sha256')=64
		AND length(metadata->>'previous_trust_sha256')=64`, connection.ID, owner.ID).Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("expected atomic digest-only audit for two updates, records=%d err=%v", audited, err)
	}
	actor := authorization.WithHumanActor(ctx, owner.ID, operatorID)
	if err := rp.workforce.DisableConnection(actor, owner.ID, space.ID, connection.ID); err != nil {
		t.Fatal(err)
	}
	prove("sso_connections.get", enterprise.ConnectionDetailRequest(space.ID, connection.ID))
	if disabled, _ := admin(http.MethodGet, "", "", http.StatusOK); disabled.Status != "disabled" {
		t.Fatal("management GET did not return the disabled connection")
	}
}
