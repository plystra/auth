package principal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/pquerna/otp/totp"
)

func TestVerifiedDomainEnforcementHTTPRollsOutAndReverts(t *testing.T) {
	ctx := t.Context()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	const adminID, employeeID, memberID = "usr_principal_actor", "usr_domain_employee", "mem_domain_employee"
	const domainName, email = "company.example", "employee@company.example"
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id,email,email_normalized,password_hash,status) VALUES ($1,$2,$2,'fixture-password-hash','active')`, employeeID, email); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO members (id,space_id,name,kind,type) VALUES ($1,$2,'Employee','user','human')`, memberID, spaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id,member_id) VALUES ($1,$2)`, employeeID, memberID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, memberID, "self:read")
	service := &enterprise.Service{Store: st, Authorization: authz, StepUp: sessions, DataKey: secret.New(strings.Repeat("d", 32))}
	sessions.SpaceSignInPolicy = service
	sessions.Factors = &factor.Service{Store: st, DataKey: service.DataKey}
	admin, err := sessions.CreateForMember(ctx, adminID, owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	adminClaims, err := sessions.VerifyAccess(ctx, admin.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	employee, err := sessions.CreateForMember(ctx, employeeID, memberID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := service.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, adminID), owner.ID, spaceID, enterprise.ConnectionInput{
		Name: "Pilot SSO", Provider: "oidc", Issuer: "https://idp.company.example", ClientID: "workforce",
		ClientSecret: "fixture-secret", RedirectURI: "https://auth.test/v1/sso/{connection_id}/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Enterprise: service, Accounts: &account.Service{
		Store: st, Authorization: authz, Sessions: sessions, SignInPolicy: service,
	}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("domain enforcement rollout", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	send := func(method, path, token, version string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(payload))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if version != "" {
			req.Header.Set("If-Match", version)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != want {
			t.Fatalf("%s %s returned %d, want %d", method, path, resp.Code, want)
		}
		return resp
	}
	root := "/v1/spaces/" + spaceID + "/domains"
	prove := func(operation string, request any) { seedStepUpProof(t, st, adminClaims.SessionID, operation, request) }
	prove("domains.create", map[string]any{
		"operation": "domains.create", "space_id": spaceID, "domain": domainName,
		"connection_id": connection.ID, "force_sso": false, "covers_subtree": false,
	})
	created := send(http.MethodPost, root, admin.AccessToken, "", map[string]any{"domain": domainName, "connection_id": connection.ID, "force_sso": false}, http.StatusOK)
	var envelope struct{ Data enterprise.Domain }
	if err := json.Unmarshal(created.Body.Bytes(), &envelope); err != nil || envelope.Data.VerificationToken == "" || envelope.Data.ETag == "" || created.Header().Get("ETag") != envelope.Data.ETag {
		t.Fatal("optional domain creation did not return its verification token and version")
	}
	pending := envelope.Data
	path := root + "/" + pending.ID
	changeProof := func(version string, force bool) {
		prove(enterprise.DomainUpdateOperation, enterprise.DomainUpdateRequest(spaceID, pending.ID, version, force))
	}
	changeWithMFA := func(version string, force bool) {
		t.Helper()
		enrolled, err := sessions.Factors.EnrollTOTPForUser(ctx, adminID, "principal-actor@example.test", "rollout approval "+strconv.FormatBool(force))
		if err != nil {
			t.Fatal(err)
		}
		code, err := totp.GenerateCode(enrolled.Secret.Value(), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		send(http.MethodPost, "/v1/auth/step-up", admin.AccessToken, "", map[string]any{
			"operation": enterprise.DomainUpdateOperation,
			"request":   enterprise.DomainUpdateRequest(spaceID, pending.ID, version, force),
			"mfa_code":  code,
		}, http.StatusOK)
	}
	change := func(version string, force bool, want int) *httptest.ResponseRecorder {
		return send(http.MethodPatch, path, admin.AccessToken, version, map[string]bool{"force_sso": force}, want)
	}
	changeProof(pending.ETag, true)
	change(pending.ETag, true, http.StatusConflict)
	service.DNSResolver = principalTXTResolver{values: []string{pending.VerificationToken}}
	prove("domains.verify", map[string]any{"operation": "domains.verify", "space_id": spaceID, "domain_id": pending.ID})
	send(http.MethodPost, path+"/verify", admin.AccessToken, "", nil, http.StatusOK)
	prove("domains.list", enterprise.SettingsListRequest("domains.list", spaceID))
	active := send(http.MethodGet, root, admin.AccessToken, "", nil, http.StatusOK)
	var listed struct{ Data []enterprise.Domain }
	if err := json.Unmarshal(active.Body.Bytes(), &listed); err != nil || len(listed.Data) != 1 || listed.Data[0].VerificationToken != "" || listed.Data[0].ETag == pending.ETag {
		t.Fatal("verified domain list did not expose only the current public version")
	}
	verified := listed.Data[0]
	change("", true, http.StatusPreconditionFailed)
	change(verified.ETag, true, http.StatusForbidden)
	changeProof(pending.ETag, true)
	change(pending.ETag, true, http.StatusPreconditionFailed)
	changeProof(verified.ETag, false)
	change(verified.ETag, true, http.StatusForbidden)

	signIn := map[string]string{"email": email, "method": "password", "space_id": spaceID}
	send(http.MethodGet, "/v1/me", employee.AccessToken, "", nil, http.StatusOK)
	started := send(http.MethodPost, "/v1/auth/sign-in", "", "", signIn, http.StatusOK)
	var attempt SignInStartOutput
	if err := json.Unmarshal(started.Body.Bytes(), &attempt.Body); err != nil || attempt.Body.Data.AttemptID == "" {
		t.Fatal("optional policy did not permit a password attempt")
	}
	if _, err := st.Pool.Exec(ctx, `CREATE FUNCTION reject_domain_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'sso.domain.policy.update' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_domain_policy_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_domain_policy_audit()`); err != nil {
		t.Fatal(err)
	}
	changeWithMFA(verified.ETag, true)
	change(verified.ETag, true, http.StatusServiceUnavailable)
	send(http.MethodGet, "/v1/me", employee.AccessToken, "", nil, http.StatusOK)
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_domain_policy_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	enabled := change(verified.ETag, true, http.StatusOK)
	if err := json.Unmarshal(enabled.Body.Bytes(), &envelope); err != nil || !envelope.Data.ForceSSO || envelope.Data.ETag == verified.ETag || enabled.Header().Get("ETag") != envelope.Data.ETag || !envelope.Data.VerifiedAt.Equal(verified.VerifiedAt) || envelope.Data.ConnectionID != connection.ID {
		t.Fatal("rollout did not preserve verified ownership and advance the version")
	}
	forced := envelope.Data
	routed := send(http.MethodPost, "/v1/auth/sign-in", "", "", signIn, http.StatusOK)
	var challenge SignInStartOutput
	if err := json.Unmarshal(routed.Body.Bytes(), &challenge.Body); err != nil || challenge.Body.Data.NextStep != "sso" || challenge.Body.Data.SSOConnectionID != connection.ID {
		t.Fatal("new employee sign-in was not routed to the required provider")
	}
	send(http.MethodPost, "/v1/auth/sign-in/"+attempt.Body.Data.AttemptID, "", "", map[string]string{"password": "fixture-only"}, http.StatusBadRequest)
	send(http.MethodGet, "/v1/me", employee.AccessToken, "", nil, http.StatusUnauthorized)
	refresh := map[string]string{"refresh_token": employee.RefreshToken}
	denied := send(http.MethodPost, "/v1/auth/refresh", "", "", refresh, http.StatusForbidden)
	if !strings.Contains(denied.Body.String(), `"code":"PERMISSION_DENIED"`) {
		t.Fatal("refresh was not rejected by the managed Space admission policy")
	}

	prove("sso_connections.delete", map[string]any{"operation": "sso_connections.delete", "space_id": spaceID, "connection_id": connection.ID})
	send(http.MethodDelete, "/v1/spaces/"+spaceID+"/sso-connections/"+connection.ID, admin.AccessToken, "", nil, http.StatusOK)
	changeWithMFA(forced.ETag, false)
	rolledBack := change(forced.ETag, false, http.StatusOK)
	if err := json.Unmarshal(rolledBack.Body.Bytes(), &envelope); err != nil || envelope.Data.ForceSSO || envelope.Data.ETag == forced.ETag {
		t.Fatal("verified domain could not revert enforcement during provider disablement")
	}
	changeProof(envelope.Data.ETag, true)
	change(envelope.Data.ETag, true, http.StatusConflict)
	send(http.MethodPost, "/v1/auth/refresh", "", "", refresh, http.StatusOK)

	var auditCount int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='sso.domain.policy.update' AND resource_id=$1 AND space_id=$2`, pending.ID, spaceID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("rollout and rollback audit count = %d, err = %v", auditCount, err)
	}
}
