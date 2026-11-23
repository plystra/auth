package principal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/stepup"
)

// Exercise a persisted invalid mapping after a valid first row, so decoding
// failure must roll back both the read proof and any partial response.
func TestSSOConnectionListProtectsSpaceProjectionAndRollsBackProof(t *testing.T) {
	ctx := t.Context()
	st, az, owner, space, sessions, signer := newPrincipalFixture(t)
	svc := &enterprise.Service{Store: st, Authorization: az, StepUp: sessions, DataKey: secret.New(strings.Repeat("d", 32))}
	approvals := &approval.Service{Store: st, Authorization: az, StepUp: sessions}
	mux := http.NewServeMux()
	(&API{Authorization: az, Sessions: sessions, Signer: signer, Approvals: approvals, Enterprise: svc}).Register(humago.New(mux, route.HumaConfig("SSO list transaction", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	const actorUser = "usr_principal_actor"
	seedTestInlineGrant(t, st, space, owner.ID, owner.ID, "auth.connections:manage")
	foreign, foreignOwner, err := az.CreateSpace(ctx, actorUser, "Private Space", "private-space")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, foreign.ID, foreignOwner.ID, foreignOwner.ID, "auth.connections:manage")
	create := func(name, spaceID, memberID string) string {
		t.Helper()
		connection, err := svc.CreateConnection(authorization.WithHumanActor(ctx, memberID, actorUser), memberID, spaceID, enterprise.ConnectionInput{
			Name: name, Provider: "oidc", Issuer: "https://issuer.example.test", ClientID: "workforce-client", ClientSecret: "test-only-canary",
			RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback",
		})
		if err != nil {
			t.Fatal(err)
		}
		return connection.ID
	}
	first, second := create("Primary", space, owner.ID), create("Secondary", space, owner.ID)
	create("Other tenant", foreign.ID, foreignOwner.ID)
	human, err := sessions.CreateForMember(ctx, actorUser, owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := sessions.VerifyAccess(t.Context(), human.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	actor, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "SSO reader"})
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, space, owner.ID, actor.ID, "auth.connections:manage")
	agentTokens, err := sessions.CreateAgentAccess(ctx, actor.ID, space, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		Data  json.RawMessage
		Error struct {
			Code    string
			Details map[string]string
		}
	}
	get := func(t *testing.T, token, approvalID, path string, want int) result {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/spaces/"+space+"/sso-connections"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if approvalID != "" {
			req.Header.Set("Approval-Id", approvalID)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var body result
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want || want != http.StatusOK && len(body.Data) != 0 {
			t.Fatalf("SSO read returned HTTP %d code %q; want %d", res.StatusCode, body.Error.Code, want)
		}
		return body
	}
	for _, kind := range []string{"human", "agent"} {
		t.Run(kind, func(t *testing.T) {
			token, approvalID := human.AccessToken, ""
			if kind == "human" {
				seedStepUpProof(t, st, claims.SessionID, "sso_connections.list", enterprise.SettingsListRequest("sso_connections.list", space))
			} else {
				token = agentTokens.AccessToken
				pending := get(t, token, "", "", 403)
				approvalID = pending.Error.Details["approval_id"]
				if approvalID == "" {
					t.Fatal("missing Agent approval")
				}
				seedStepUpProof(t, st, claims.SessionID, "approvals.approve", map[string]any{"approval_id": approvalID})
				result := applicationAuditRequest(t, handler, http.MethodPost, "/v1/approvals/"+approvalID+"/approve", human.AccessToken, "req_approve_sso_list_retry", nil)
				if result.Code != http.StatusOK {
					t.Fatalf("approval failed: status=%d", result.Code)
				}
				if r := get(t, token, approvalID, "/"+first, 403); r.Error.Code != "APPROVAL_REQUIRED" {
					t.Fatalf("detail accepted list approval: %q", r.Error.Code)
				}
				digest, err := stepup.DigestValue(enterprise.SettingsListRequest("sso_connections.list", space))
				if err != nil {
					t.Fatal(err)
				}
				proof := authorization.WithGovernanceApproval(ctx, approvalID, "sso_connections.list", space, digest)
				_, err = svc.GetConnection(proof, actor.ID, space, first)
				assertPrincipalError(t, err, "APPROVAL_REQUIRED")
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE sso_connections SET role_mappings='{"group":17}' WHERE id=$1`, second); err != nil {
				t.Fatal(err)
			}
			if r := get(t, token, approvalID, "", 503); r.Error.Code != "UNAVAILABLE" {
				t.Fatalf("invalid list projection returned %q", r.Error.Code)
			}
			if _, err := st.Pool.Exec(ctx, `UPDATE sso_connections SET role_mappings='{}' WHERE id=$1`, second); err != nil {
				t.Fatal(err)
			}
			result := get(t, token, approvalID, "", 200)
			var rows []map[string]json.RawMessage
			if err := json.Unmarshal(result.Data, &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || string(rows[0]["id"]) != `"`+first+`"` || string(rows[1]["id"]) != `"`+second+`"` {
				t.Fatal("list lost its Space boundary, order or configuration")
			}
			for _, row := range rows {
				for _, field := range []string{"client_secret", "client_secret_ciphertext", "saml_idp_certificate", "configured_by_member_id", "configured_by_user_id"} {
					if _, ok := row[field]; ok {
						t.Fatalf("list exposed a private field %q", field)
					}
				}
			}
		})
	}
}
