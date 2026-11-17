package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/space"
)

func TestRegistrationAuditHTTPPreservesDefaultMembershipAndPublicIdentity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, authz, actor, otherSpaceID, sessions, _ := newPrincipalFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'open', require_email_verification = false`); err != nil {
		t.Fatal(err)
	}
	accounts := &account.Service{Store: st, Authorization: authz, Sessions: sessions, Settings: &space.Service{Store: st}, Passwords: security.DefaultPasswordHasher()}
	mux := http.NewServeMux()
	(&API{Accounts: accounts, Sessions: sessions, Authorization: authz}).Register(humago.New(mux, route.HumaConfig("registration audit", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	otherTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	// A public registration must not inherit an unrelated bearer identity.
	out := applicationAuditRequest(t, handler, http.MethodPost, "/v1/auth/sign-up", otherTokens.AccessToken, "req_registration_audit",
		map[string]string{"email": "private-registered@example.test", "password": "a-long-registration-password"})
	var result struct{ Data account.AuthResult }
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &result) != nil || result.Data.Tokens == nil {
		t.Fatalf("registration failed: status=%d", out.Code)
	}
	user, tokens := result.Data.User, result.Data.Tokens
	var memberID string
	var version int64
	if err := st.Pool.QueryRow(ctx, `SELECT m.id, s.policy_version FROM members m JOIN user_members b ON b.member_id = m.id JOIN spaces s ON s.id = m.space_id WHERE b.user_id = $1 AND m.space_id = $2`, user.ID, account.DefaultSpaceID).Scan(&memberID, &version); err != nil {
		t.Fatal(err)
	}
	// The fixture explicitly provisions an observer; registration itself only
	// grants the documented default role, never audit-reading privileges.
	seedTestInlineGrant(t, st, account.DefaultSpaceID, "system", memberID, "auth.audit:read")
	page := decodeAuditPage(t, getAuditHTTP(handler, tokens.AccessToken, "/v1/spaces/"+account.DefaultSpaceID+"/audit-logs?request_id=req_registration_audit&member_id="+memberID))
	if len(page.Body.Data) != 2 {
		t.Fatalf("registration has %d queryable events, want 2", len(page.Body.Data))
	}
	for _, event := range page.Body.Data {
		if event.MemberID != memberID || event.MemberType != "human" || event.UserID != user.ID || event.SpaceID != account.DefaultSpaceID ||
			event.ResourceGroupID != "" || len(event.OwnerChain) != 0 || event.CredentialType != "public_registration" || event.Plane != "principal" ||
			event.Outcome != "success" || event.PolicyVersion != version || event.PermissionKey != "" {
			t.Fatal("registration audit misrepresents the new identity or policy")
		}
		var metadata map[string]any
		if json.Unmarshal(event.Metadata, &metadata) != nil || metadata["identity_source"] != "registration_result" || metadata["owner_chain_complete"] != true {
			t.Fatal("registration identity provenance is not explicit")
		}
		switch event.Action {
		case "auth.register":
			if event.ActorType != "public" || event.ActorID != user.ID || event.ResourceType != "user" || event.ResourceID != user.ID {
				t.Fatal("registration audit claims an authenticated actor")
			}
		case "member.default_bind":
			if event.ActorType != "system" || event.ActorID != "system" || event.ResourceType != "member" || event.ResourceID != memberID ||
				metadata["binding_user_id"] != user.ID || metadata["binding_policy"] != "single" || metadata["role_id"] == "" || metadata["grant_id"] == "" {
				t.Fatal("default membership audit has incorrect system provenance")
			}
		default:
			t.Fatal("unexpected registration audit event")
		}
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{tokens.AccessToken, tokens.RefreshToken, otherTokens.AccessToken, user.Email, "a-long-registration-password", "$argon2id$"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("registration audit exposed credentials or private labels")
		}
	}
	other := decodeAuditPage(t, getAuditHTTP(handler, otherTokens.AccessToken, "/v1/spaces/"+otherSpaceID+"/audit-logs?request_id=req_registration_audit"))
	if len(other.Body.Data) != 0 {
		t.Fatal("registration events leaked into another Space")
	}
}
