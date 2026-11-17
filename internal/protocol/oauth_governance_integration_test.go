package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/approval"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/plane/principal"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
)

func newGovernanceFixture(t *testing.T) redemptionFixture {
	t.Helper()
	f := newRedemptionFixture(t)
	f.handler = route.Middleware(route.Principal, f.handler)
	if _, err := f.store.Pool.Exec(context.Background(), `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ('grt_governance_consent', $1, '["auth.members:read"]', $2, 'space', $1, $3)`, f.owner.SpaceID, f.agent.ID, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	return f
}

func governanceForm(f redemptionFixture) url.Values {
	form := f.form("refresh_token")
	form.Set("resource", security.DefaultApplicationAudience)
	form.Set("scope", "auth.members:read")
	return form
}

func TestOAuthGovernanceRefreshKeepsIdentityAudienceScopeAndRotation(t *testing.T) {
	f := newGovernanceFixture(t)
	ctx := context.Background()
	form := governanceForm(f)
	form.Set("scope", " auth.members:read auth.members:read ")
	out := f.request(ctx, form)
	token := delegationAuditToken(t, out)
	var body struct {
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if json.Unmarshal(out.Body.Bytes(), &body) != nil || body.RefreshToken == "" || body.RefreshToken == f.refresh || body.Scope != "auth.members:read" {
		t.Fatal("governance response omitted explicit scope or rotated refresh credential")
	}
	claims, active, err := f.sessions.Introspect(ctx, token, security.DefaultApplicationAudience)
	if err != nil || !active || claims.Type != "agent" || claims.Subject != f.agent.ID || claims.MemberID != f.agent.ID ||
		claims.SpaceID != f.owner.SpaceID || len(claims.Scopes) != 1 || claims.Scopes[0] != body.Scope ||
		claims.Actor == nil || claims.Actor.Subject != f.owner.ID || claims.Actor.Actor != nil ||
		claims.ExpiresAt > time.Now().Add(time.Minute).Unix() || claims.ExpiresAt > f.agent.ExpiresAt.Unix() {
		t.Fatal("governance token changed identity, authority restriction, ownership, or lifetime")
	}
	for _, audience := range []string{"app_redemption", "app_other"} {
		if _, active, err := f.sessions.Introspect(ctx, token, audience); err != nil || active {
			t.Fatal("Auth governance token authenticated to a SaaS audience")
		}
	}
	page, err := f.applications.Authorization.ListAuditLogs(ctx, f.owner.ID,
		authorization.AuditQuery{SpaceID: f.owner.SpaceID, Action: "agent.access.issue", MemberID: f.agent.ID})
	if err != nil || len(page.Events) != 1 {
		t.Fatal("governance issuance did not produce a queryable audit")
	}
	event := page.Events[0]
	var metadata map[string]any
	if json.Unmarshal(event.Metadata, &metadata) != nil {
		t.Fatal("governance audit metadata is invalid")
	}
	if event.ApplicationID != "app_redemption" || event.CredentialType != "oauth_refresh_token" || event.Plane != "principal" ||
		len(event.OwnerChain) != 1 || event.OwnerChain[0].MemberID != f.owner.ID ||
		metadata["audience"] != "default" || metadata["scope"] != "auth.members:read" {
		t.Fatal("governance audit omitted verified client, ownership, audience, or scope")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{token, body.RefreshToken, f.refresh} {
		if strings.Contains(string(encoded), credential) {
			t.Fatal("governance audit exposed a credential")
		}
	}
	// The successor belongs to the same family and returns to the client audience
	// when resource is omitted; it does not silently retain Auth authority.
	form = f.form("refresh_token")
	form.Set("refresh_token", body.RefreshToken)
	saasToken := delegationAuditToken(t, f.request(ctx, form))
	if _, active, err := f.sessions.Introspect(ctx, saasToken, "app_redemption"); err != nil || !active {
		t.Fatal("successor could not refresh back to the original SaaS audience")
	}
	if _, active, err := f.sessions.Introspect(ctx, saasToken, security.DefaultApplicationAudience); err != nil || active {
		t.Fatal("SaaS successor retained the governance audience")
	}
	var families int
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(DISTINCT family_id) FROM agent_credentials WHERE member_id = $1`, f.agent.ID).Scan(&families); err != nil || families != 1 {
		t.Fatal("governance refresh introduced a separate refresh family")
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_governance_consent'`); err != nil {
		t.Fatal(err)
	}
	decision, _, err := f.applications.Authorization.Check(ctx, authorization.CheckRequest{
		MemberID: f.agent.ID, Permission: "auth.members:read", ResourceSpace: f.owner.SpaceID, TokenScopes: claims.Scopes,
	})
	if err != nil || decision.Effect != engine.Deny {
		t.Fatal("an issued governance token retained revoked authority")
	}
}

func TestOAuthGovernanceRefreshRejectsUnconsentedAndInactiveAuthority(t *testing.T) {
	for _, scenario := range []string{"MissingScope", "TooManyScopes", "OtherResource", "Consent", "RoleOnly", "Manifest", "InstallationPermissions", "InstallationInactive", "ClientInactive", "OwnerAuthority", "OwnerInactive", "Disabled", "HumanOnly", "Expired"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGovernanceFixture(t)
			ctx := context.Background()
			form := governanceForm(f)
			code := "invalid_scope"
			var query string
			switch scenario {
			case "MissingScope":
				form.Del("scope")
			case "TooManyScopes":
				scopes := make([]string, 257)
				for i := range scopes {
					scopes[i] = fmt.Sprintf("test:permission%d", i)
				}
				form.Set("scope", strings.Join(scopes, " "))
			case "OtherResource":
				form.Set("resource", "app_other")
				code = "invalid_target"
			case "Consent", "RoleOnly":
				query = `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_governance_consent'`
				if scenario == "RoleOnly" {
					if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
						(id, space_id, role_id, grantee_member_id, scope, anchor_space_id, granted_by)
						SELECT 'grt_unconsented_role', $1, id, $2, 'space', $1, $3 FROM roles WHERE space_id = $1 AND name = 'administrator'`, f.owner.SpaceID, f.agent.ID, f.owner.ID); err != nil {
						t.Fatal(err)
					}
				}
			case "Manifest":
				query = `UPDATE applications SET allowed_scopes = '[]' WHERE id = 'app_redemption'`
			case "InstallationPermissions":
				query = `UPDATE application_installations SET approved_permissions = '[]' WHERE id = 'ins_redemption'`
			case "InstallationInactive":
				query, code = `UPDATE application_installations SET status = 'suspended' WHERE id = 'ins_redemption'`, "invalid_grant"
			case "ClientInactive":
				query, code = `UPDATE applications SET status = 'suspended' WHERE id = 'app_redemption'`, "invalid_client"
			case "OwnerAuthority":
				query = `DELETE FROM role_permissions WHERE permission_id = (SELECT id FROM permissions WHERE key = 'auth.members:read')`
			case "OwnerInactive":
				query = `UPDATE members SET status = 'suspended' WHERE type = 'human'`
			case "Disabled":
				query = `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.members:read'`
			case "HumanOnly":
				query = `UPDATE permissions SET principal_kinds = '["human"]' WHERE key = 'auth.members:read'`
			case "Expired":
				query, code = `UPDATE members SET expires_at = now() WHERE source = 'oauth'`, "invalid_grant"
			}
			if query != "" {
				if _, err := f.store.Pool.Exec(ctx, query); err != nil {
					t.Fatal(err)
				}
			}
			out := f.request(ctx, form)
			if out.Code >= 500 || out.Code < 400 || !strings.Contains(out.Body.String(), code) || strings.Contains(out.Body.String(), "access_token") {
				t.Fatalf("governance refresh bypassed %s: status=%d", scenario, out.Code)
			}
			f.assertUnchanged(t)
		})
	}
}

func TestOAuthGovernanceRefreshRollsBackAndAllowsRetry(t *testing.T) {
	for _, failure := range []string{"Settings", "Audit", "Commit"} {
		t.Run(failure, func(t *testing.T) {
			f := newGovernanceFixture(t)
			ctx := context.Background()
			settings := f.sessions.Settings
			if failure == "Settings" {
				f.sessions.Settings = func(context.Context) (session.Settings, error) {
					return session.Settings{}, errors.New("injected settings failure")
				}
			} else {
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_governance_issue() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.action = 'agent.access.issue' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`); err != nil {
					t.Fatal(err)
				}
				trigger := `CREATE TRIGGER reject_governance_issue BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_governance_issue()`
				if failure == "Commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_governance_issue AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_governance_issue()`
				}
				if _, err := f.store.Pool.Exec(ctx, trigger); err != nil {
					t.Fatal(err)
				}
			}
			out := f.request(ctx, governanceForm(f))
			if out.Code != http.StatusServiceUnavailable || strings.Contains(out.Body.String(), "access_token") {
				t.Fatalf("governance credentials escaped %s failure: status=%d", failure, out.Code)
			}
			f.assertUnchanged(t)
			f.sessions.Settings = settings
			if failure != "Settings" {
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_governance_issue ON audit_logs`); err != nil {
					t.Fatal(err)
				}
			}
			delegationAuditToken(t, f.request(ctx, governanceForm(f)))
		})
	}
}

func TestOAuthGovernanceRefreshRechecksAuthorityAfterLockWait(t *testing.T) {
	for _, change := range []string{"Manifest", "Consent", "Owner", "Expiry"} {
		t.Run(change, func(t *testing.T) {
			f := newGovernanceFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			mutation, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
			if err := f.store.InTx(mutation.Context(ctx), func(q *db.Queries) error {
				if change == "Manifest" {
					_, err := f.applications.OAuthClientByIDTx(ctx, q, "app_redemption")
					return err
				}
				return member.LockChainsTx(ctx, q, f.agent.ID)
			}); err != nil {
				t.Fatal(err)
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() { response <- f.request(ctx, governanceForm(f)) }()
			waitForRedemptionLock(t, ctx, f.store, response)
			if err := f.store.InTx(mutation.Context(ctx), func(q *db.Queries) error {
				tx, _ := q.Transaction()
				var query string
				switch change {
				case "Manifest":
					query = `UPDATE applications SET allowed_scopes = '[]' WHERE id = 'app_redemption'`
				case "Consent":
					query = `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_governance_consent'`
				case "Owner":
					query = `UPDATE members SET status = 'suspended' WHERE type = 'human'`
				case "Expiry":
					query = `UPDATE agent_credentials SET expires_at = clock_timestamp() WHERE kind = 'oauth_refresh'`
				}
				_, err := tx.Exec(ctx, query)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := mutation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			out := <-response
			if out.Code < 400 || out.Code >= 500 || strings.Contains(out.Body.String(), "access_token") {
				t.Fatalf("governance issuance ignored committed %s change: status=%d", change, out.Code)
			}
			f.assertUnchanged(t)
		})
	}
}

func TestOAuthScopedRefreshRetainsDeprecatedConsent(t *testing.T) {
	for _, resource := range []string{security.DefaultApplicationAudience, "app_redemption"} {
		t.Run(resource, func(t *testing.T) {
			f := newGovernanceFixture(t)
			ctx := context.Background()
			if _, err := f.store.Pool.Exec(ctx, `UPDATE permissions SET status = 'deprecated' WHERE key = 'auth.members:read'`); err != nil {
				t.Fatal(err)
			}
			form := governanceForm(f)
			form.Set("resource", resource)
			token := delegationAuditToken(t, f.request(ctx, form))
			claims, active, err := f.sessions.Introspect(ctx, token, resource)
			if err != nil || !active || len(claims.Scopes) != 1 || claims.Scopes[0] != "auth.members:read" {
				t.Fatal("scoped refresh discarded existing deprecated consent or its explicit restriction")
			}
		})
	}
}

func TestOAuthGovernanceRefreshConcurrentReplayRevokesSharedFamily(t *testing.T) {
	f := newGovernanceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { responses <- f.request(ctx, governanceForm(f)) }()
	}
	first, second := <-responses, <-responses
	if first.Code > second.Code {
		first, second = second, first
	}
	if first.Code != http.StatusOK || second.Code != http.StatusBadRequest || !strings.Contains(second.Body.String(), "invalid_grant") {
		t.Fatalf("concurrent governance refresh statuses=%d,%d", first.Code, second.Code)
	}
	var issued struct {
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(first.Body.Bytes(), &issued) != nil || issued.RefreshToken == "" {
		t.Fatal("successful governance refresh omitted its successor")
	}
	for _, resource := range []string{security.DefaultApplicationAudience, "app_redemption"} {
		form := governanceForm(f)
		form.Set("resource", resource)
		form.Set("refresh_token", issued.RefreshToken)
		out := f.request(ctx, form)
		if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_grant") {
			t.Fatal("governance refresh replay left a live successor in the shared family")
		}
	}
	var live, issuance, replay int
	if err := f.store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agent_credentials WHERE revoked_at IS NULL),
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.access.issue'),
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.oauth_refresh.replay')`).Scan(&live, &issuance, &replay); err != nil || live != 0 || issuance != 1 || replay != 1 {
		t.Fatal("concurrent governance replay did not atomically revoke the shared family with one issuance")
	}
}

func TestOAuthGovernanceRefreshPreservesRequestBoundApproval(t *testing.T) {
	f := newGovernanceFixture(t)
	ctx := context.Background()
	if _, err := f.store.Pool.Exec(ctx, `UPDATE applications SET allowed_scopes = '["auth.bindings:manage"]' WHERE id = 'app_redemption';
		UPDATE application_installations SET approved_permissions = '["auth.bindings:manage"]' WHERE id = 'ins_redemption';
		UPDATE authorization_grants SET permission_keys = '["auth.bindings:manage"]' WHERE id = 'grt_governance_consent';
		INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at)
		VALUES ('usr_governance_invitee', 'governance-invitee@example.test', 'governance-invitee@example.test', 'test-hash', 'active', now())`); err != nil {
		t.Fatal(err)
	}
	form := governanceForm(f)
	form.Set("scope", "auth.bindings:manage")
	response := f.request(ctx, form)
	token := delegationAuditToken(t, response)
	var issued struct {
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(response.Body.Bytes(), &issued) != nil || issued.RefreshToken == "" {
		t.Fatal("approval-restricted root credential omitted its refresh successor")
	}
	authz := f.applications.Authorization
	target, err := authz.CreateMember(ctx, f.owner.ID, "", f.owner.SpaceID, "Shared target", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	approvals := &approval.Service{Store: f.store, Authorization: authz, StepUp: f.sessions}
	var mux http.ServeMux
	(&principal.API{Authorization: authz, Sessions: f.sessions, Signer: f.sessions.Signer, Agents: f.agents, Approvals: approvals}).Register(
		humago.New(&mux, route.HumaConfig("OAuth governance approval", "1.0.0")))
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+f.owner.SpaceID+"/members/"+target.ID+"/users",
		strings.NewReader(`{"user_id":"usr_governance_invitee"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	out := httptest.NewRecorder()
	route.Middleware(route.Principal, &mux).ServeHTTP(out, req)
	var denied struct {
		Error struct {
			Code    string            `json:"code"`
			Details map[string]string `json:"details"`
		} `json:"error"`
	}
	if out.Code != http.StatusForbidden || json.Unmarshal(out.Body.Bytes(), &denied) != nil || denied.Error.Code != "APPROVAL_REQUIRED" ||
		!strings.HasPrefix(denied.Error.Details["approval_id"], "apr_") {
		t.Fatalf("governance credential bypassed request-bound approval: status=%d", out.Code)
	}
	var bindings, pending int
	if err := f.store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM user_members WHERE member_id = $1),
		(SELECT count(*) FROM approval_requests WHERE agent_member_id = $2 AND status = 'pending')`, target.ID, f.agent.ID).Scan(&bindings, &pending); err != nil || bindings != 0 || pending != 1 {
		t.Fatal("unapproved governance operation changed the binding or lost its approval request")
	}
	allowed, err := authz.ValidateTokenScopes(ctx, f.agent.ID, []string{"auth.bindings:manage"})
	if err != nil || allowed {
		t.Fatal("root credential issuance relaxed the child delegation rule")
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = 'grt_governance_consent'`); err != nil {
		t.Fatal(err)
	}
	form.Set("refresh_token", issued.RefreshToken)
	if out := f.request(ctx, form); out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_scope") {
		t.Fatal("approval-required scope replaced revoked consent")
	}
}
