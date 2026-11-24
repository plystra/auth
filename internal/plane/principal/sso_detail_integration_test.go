package principal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

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

func TestSSOConnectionDetailScopesAndProtectsConfiguration(t *testing.T) {
	ctx := t.Context()
	st, az, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	seedTestInlineGrant(t, st, spaceID, owner.ID, owner.ID, "auth.connections:manage")
	service := &enterprise.Service{Store: st, Authorization: az, StepUp: sessions, DataKey: secret.New(strings.Repeat("d", 32))}
	approvals := &approval.Service{Store: st, Authorization: az, StepUp: sessions}
	mux := http.NewServeMux()
	(&API{Authorization: az, Sessions: sessions, Signer: signer, Approvals: approvals, Enterprise: service}).Register(humago.New(mux, route.HumaConfig("SSO connection detail", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	const actorUser = "usr_principal_actor"
	makeConnection := func(space, member, name string) enterprise.Connection {
		t.Helper()
		connection, err := service.CreateConnection(authorization.WithHumanActor(ctx, member, actorUser), member, space, enterprise.ConnectionInput{
			Name: name, Provider: "oidc", Issuer: "https://issuer.example.test", ClientID: "workforce-client", ClientSecret: "test-only-canary",
			RedirectURI: "https://auth.example.test/v1/sso/{connection_id}/callback", CoversSubtree: true, GroupsClaim: "teams",
		})
		if err != nil {
			t.Fatal(err)
		}
		return connection
	}
	connection := makeConnection(spaceID, owner.ID, "Workforce")
	other := makeConnection(spaceID, owner.ID, "Another connection")
	otherSpace, otherOwner, err := az.CreateSpace(ctx, actorUser, "Separate Space", "separate-space")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, otherSpace.ID, otherOwner.ID, otherOwner.ID, "auth.connections:manage")
	foreign := makeConnection(otherSpace.ID, otherOwner.ID, "Private configuration")
	human, err := sessions.CreateForMember(ctx, actorUser, owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := sessions.VerifyAccess(t.Context(), human.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	type response struct {
		Data  map[string]json.RawMessage
		Error struct {
			Code    string
			Message string
			Details map[string]string
		}
	}
	get := func(t *testing.T, token, id, approvalID string, wantStatus int, wantCode string) response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/spaces/"+spaceID+"/sso-connections/"+id, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if approvalID != "" {
			req.Header.Set("Approval-Id", approvalID)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var out response
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != wantStatus || !strings.EqualFold(out.Error.Code, wantCode) || wantStatus != http.StatusOK && out.Data != nil {
			t.Fatalf("detail returned HTTP %d, code %q, want %d %q", res.StatusCode, out.Error.Code, wantStatus, wantCode)
		}
		return out
	}
	prove := func(t *testing.T, id string) {
		t.Helper()
		seedStepUpProof(t, st, claims.SessionID, "sso_connections.get", map[string]any{"operation": "sso_connections.get", "space_id": spaceID, "connection_id": id})
	}
	checkPublic := func(t *testing.T, out response) {
		t.Helper()
		keys := []string{"id", "space_id", "name", "provider", "issuer", "client_id", "token_endpoint_auth_method", "redirect_uri", "groups_claim", "role_mappings", "covers_subtree", "status", "created_at", "updated_at"}
		for key := range out.Data {
			if !slices.Contains(keys, key) {
				t.Fatalf("non-public connection field %q", key)
			}
		}
		if len(out.Data) != len(keys) || string(out.Data["id"]) != `"`+connection.ID+`"` || string(out.Data["space_id"]) != `"`+spaceID+`"` ||
			string(out.Data["groups_claim"]) != `"teams"` || string(out.Data["covers_subtree"]) != "true" || string(out.Data["role_mappings"]) != "{}" ||
			string(out.Data["token_endpoint_auth_method"]) != `"client_secret_basic"` {
			t.Fatal("detail did not return the expected public connection configuration")
		}
	}
	t.Run("human requires target-bound single-use step-up", func(t *testing.T) {
		get(t, "", connection.ID, "", 401, "UNAUTHENTICATED")
		get(t, human.AccessToken, connection.ID, "", 403, "STEP_UP_REQUIRED")
		prove(t, connection.ID)
		actorCtx := authorization.WithHumanActor(ctx, owner.ID, actorUser)
		_, err := service.GetConnection(actorCtx, owner.ID, spaceID, connection.ID)
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
		digest, err := stepup.DigestValue(enterprise.ConnectionDetailRequest(spaceID, connection.ID))
		if err != nil {
			t.Fatal(err)
		}
		proofCtx := stepup.WithRequirement(actorCtx, stepup.Requirement{SessionID: claims.SessionID, Operation: "sso_connections.get", Digest: digest})
		_, err = service.GetConnection(proofCtx, owner.ID, spaceID, other.ID)
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
		otherSession, err := sessions.CreateForMember(ctx, actorUser, otherOwner.ID, nil, "test", 1)
		if err != nil {
			t.Fatal(err)
		}
		otherClaims, err := sessions.VerifyAccess(t.Context(), otherSession.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		seedStepUpProof(t, st, otherClaims.SessionID, "sso_connections.get", enterprise.ConnectionDetailRequest(spaceID, connection.ID))
		proofCtx = stepup.WithRequirement(actorCtx, stepup.Requirement{SessionID: otherClaims.SessionID, Operation: "sso_connections.get", Digest: digest})
		_, err = service.GetConnection(proofCtx, owner.ID, spaceID, connection.ID)
		assertPrincipalError(t, err, "STEP_UP_REQUIRED")
		get(t, human.AccessToken, other.ID, "", 403, "STEP_UP_REQUIRED")
		checkPublic(t, get(t, human.AccessToken, connection.ID, "", 200, ""))
		get(t, human.AccessToken, connection.ID, "", 403, "STEP_UP_REQUIRED")
	})
	t.Run("a group grant cannot read Space configuration", func(t *testing.T) {
		group, err := az.CreateGroup(ctx, owner.ID, spaceID, "Team", "")
		if err != nil {
			t.Fatal(err)
		}
		member, err := az.CreateMember(ctx, owner.ID, actorUser, spaceID, "Group manager", "human", "single")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants(id,space_id,permission_keys,grantee_member_id,scope,anchor_group_id,granted_by)
			VALUES ('grt_group_sso_detail',$1,'["auth.connections:manage"]',$2,'group',$3,$4)`, spaceID, member.ID, group.ID, owner.ID); err != nil {
			t.Fatal(err)
		}
		tokens, err := sessions.CreateForMember(ctx, actorUser, member.ID, nil, "test", 1)
		if err != nil {
			t.Fatal(err)
		}
		get(t, tokens.AccessToken, connection.ID, "", 403, "SCOPE_OUT_OF_BOUNDS")
		get(t, tokens.AccessToken, "con_missing", "", 403, "SCOPE_OUT_OF_BOUNDS")
	})
	t.Run("foreign and missing detail are indistinguishable", func(t *testing.T) {
		var message string
		for _, id := range []string{foreign.ID, "con_missing"} {
			prove(t, id)
			out := get(t, human.AccessToken, id, "", 404, "NOT_FOUND")
			if message != "" && out.Error.Message != message {
				t.Fatal("response disclosed a foreign connection")
			}
			message = out.Error.Message
			var preserved bool
			if err := st.Pool.QueryRow(ctx, "SELECT step_up_digest IS NOT NULL FROM sessions WHERE id=$1", claims.SessionID).Scan(&preserved); err != nil || !preserved {
				t.Fatalf("failed detail lookup consumed a proof: %v", err)
			}
		}
	})
	t.Run("Agent uses current authority and target-bound approval", func(t *testing.T) {
		created, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "SSO reader", ExpiresAt: time.Now().UTC().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		seedTestInlineGrant(t, st, spaceID, owner.ID, created.ID, "auth.connections:manage")
		tokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
		if err != nil {
			t.Fatal(err)
		}
		approve := func(id string) string {
			t.Helper()
			pending := get(t, tokens.AccessToken, id, "", 403, "APPROVAL_REQUIRED")
			approvalID := pending.Error.Details["approval_id"]
			if approvalID == "" {
				t.Fatal("approval request omitted its ID")
			}
			seedStepUpProof(t, st, claims.SessionID, "approvals.approve", map[string]any{"approval_id": approvalID})
			result := applicationAuditRequest(t, handler, http.MethodPost, "/v1/approvals/"+approvalID+"/approve", human.AccessToken, "req_approve_sso_detail", nil)
			if result.Code != http.StatusOK {
				t.Fatalf("owner approval returned %d", result.Code)
			}
			return approvalID
		}
		approvalID := approve(connection.ID)
		digest, err := stepup.DigestValue(enterprise.ConnectionDetailRequest(spaceID, connection.ID))
		if err != nil {
			t.Fatal(err)
		}
		wrongTarget := authorization.WithGovernanceApproval(ctx, approvalID, "sso_connections.get", spaceID, digest)
		_, err = service.GetConnection(wrongTarget, created.ID, spaceID, other.ID)
		assertPrincipalError(t, err, "APPROVAL_REQUIRED")
		get(t, tokens.AccessToken, other.ID, approvalID, 403, "APPROVAL_REQUIRED")
		checkPublic(t, get(t, tokens.AccessToken, connection.ID, approvalID, 200, ""))
		get(t, tokens.AccessToken, connection.ID, approvalID, 403, "APPROVAL_REQUIRED")
		foreignApproval := approve(foreign.ID)
		get(t, tokens.AccessToken, foreign.ID, foreignApproval, 404, "NOT_FOUND")
		var status string
		if err := st.Pool.QueryRow(ctx, "SELECT status FROM approval_requests WHERE id=$1", foreignApproval).Scan(&status); err != nil || status != "approved" {
			t.Fatalf("failed detail read committed approval consumption: status=%q err=%v", status, err)
		}
		secondApproval := approve(connection.ID)
		if _, err := st.Pool.Exec(ctx, "UPDATE members SET status='suspended' WHERE id=$1", owner.ID); err != nil {
			t.Fatal(err)
		}
		get(t, tokens.AccessToken, connection.ID, secondApproval, 403, "OWNER_INACTIVE")
	})
}
