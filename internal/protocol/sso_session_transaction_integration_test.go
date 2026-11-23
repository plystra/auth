package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/security"
)

func TestEnterpriseSSOCommitsLoginAndSessionTogether(t *testing.T) {
	for _, method := range []string{"oidc", "saml"} {
		for _, fault := range []string{"sessions", "refresh_tokens", "signing", "audit_logs", "commit"} {
			t.Run(method+"/"+fault, func(t *testing.T) {
				f := newJITMappingFixture(t, false)
				var mux http.ServeMux
				(HTTP{Enterprise: f.svc}).Register(&mux)
				request := ssoSessionRequest(t, f, &mux, method)
				before := f.counts(t)
				restore := breakSSOSessionIssuance(t, f, fault)
				status, out := request()
				restore()
				if status != http.StatusServiceUnavailable || out.Error.Code != "temporarily_unavailable" || out.Data != nil {
					t.Fatalf("failed login returned status=%d code=%q; want a service error without credentials", status, out.Error.Code)
				}
				if after := f.counts(t); after != before {
					t.Fatalf("failed login committed effects: before=%v after=%v", before, after)
				}
				if method == "oidc" {
					// The identity provider may have consumed the original authorization code.
					request = ssoSessionRequest(t, f, &mux, method)
				}
				status, out = request()
				if status != http.StatusOK || out.Data == nil || out.Data.Tokens == nil || out.Data.Tokens.RefreshToken == "" {
					t.Fatalf("login after repair returned status=%d code=%q; want a complete session", status, out.Error.Code)
				}
				claims, err := f.svc.Sessions.VerifyAccess(out.Data.Tokens.AccessToken)
				if err != nil || claims.Subject != out.Data.User.ID || claims.MemberID == "" ||
					claims.SessionID != out.Data.Tokens.SessionID || !slices.Equal(claims.AMR, []string{method}) {
					t.Fatal("successful login returned an invalid member-bound access token")
				}
				want := before
				for i := range want {
					want[i]++
				}
				if method == "oidc" {
					want[4]++ // The OIDC fixture also maps the engineering role.
				}
				if after := f.counts(t); after != want {
					t.Fatalf("successful login committed unexpected effects: before=%v after=%v want=%v", before, after, want)
				}
			})
		}
	}
}

type ssoSessionResponse struct {
	Data  *account.AuthResult
	Error struct{ Code string }
}

func ssoSessionRequest(t *testing.T, f *jitMappingFixture, mux *http.ServeMux, method string) func() (int, ssoSessionResponse) {
	t.Helper()
	var path, contentType string
	var payload []byte
	if method == "oidc" {
		in := f.start(t, "new-oidc-identity", "engineering")
		path = "/v1/sso/" + in.ConnectionID + "/callback"
		contentType = "application/json"
		var err error
		payload, err = json.Marshal(map[string]string{"state": in.State, "code": in.Code, "redirect_uri": f.connection.RedirectURI})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		f.svc.Issuer = "https://auth.test"
		metadata, signer := newSAMLTestIssuer(t)
		actor := authorization.WithHumanActor(t.Context(), f.owner, "usr_sso_http_owner")
		connection, err := f.svc.CreateConnection(actor, f.owner, f.space, enterprise.ConnectionInput{
			Name: "SAML session test", Provider: "saml", SAMLMetadata: metadata,
			RedirectURI: f.svc.Issuer + "/v1/sso/{connection_id}/callback",
		})
		if err != nil {
			t.Fatal(err)
		}
		request := samlLoginRequest(t, t.Context(), mux, connection, signer, false)
		defer func() { _ = request.Body.Close() }()
		path, contentType = request.URL.RequestURI(), request.Header.Get("Content-Type")
		payload, err = io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
	}
	return func() (int, ssoSessionResponse) {
		server := httptest.NewServer(mux)
		defer server.Close()
		response, err := server.Client().Post(server.URL+path, contentType, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		var body ssoSessionResponse
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
}

func breakSSOSessionIssuance(t *testing.T, f *jitMappingFixture, fault string) func() {
	t.Helper()
	if fault == "signing" {
		signer := f.svc.Sessions.Signer
		f.svc.Sessions.Signer = &security.Signer{}
		return func() { f.svc.Sessions.Signer = signer }
	}
	table := fault
	trigger := "CREATE TRIGGER reject_sso_login_write BEFORE INSERT ON " + table + " FOR EACH ROW"
	if fault == "commit" {
		table = "sessions"
		trigger = "CREATE CONSTRAINT TRIGGER reject_sso_login_write AFTER INSERT ON sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW"
	}
	f.exec(t, `CREATE FUNCTION reject_sso_login_write() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'test login write failure'; END $$;
		`+trigger+` EXECUTE FUNCTION reject_sso_login_write()`)
	return func() { f.exec(t, "ALTER TABLE "+table+" DISABLE TRIGGER reject_sso_login_write") }
}
