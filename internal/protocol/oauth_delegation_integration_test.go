package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type oauthDelegationFixture struct {
	redemptionFixture
	child       agent.Agent
	childKey    string
	parentToken string
}

func newOAuthDelegationFixture(t *testing.T) oauthDelegationFixture {
	t.Helper()
	ctx := context.Background()
	f := oauthDelegationFixture{redemptionFixture: newRedemptionFixture(t)}
	f.handler = route.Middleware(route.Principal, f.handler)
	var err error
	f.child, f.childKey, err = f.agents.Create(ctx, agent.CreateInput{
		OwnerMemberID: f.agent.ID, Name: "delegated reader", Source: "delegation", ExpiresAt: f.agent.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{f.agent.ID, f.child.ID} {
		if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
			(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
			VALUES ($1, $2, '["auth.members:read"]', $3, 'space', $2, $4)`, "grt_"+id, f.owner.SpaceID, id, f.owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	f.parentToken = delegationAuditToken(t, f.request(ctx, f.form("authorization_code")))
	return f
}

func (f oauthDelegationFixture) exchange(ctx context.Context, resource, scope string) *httptest.ResponseRecorder {
	return f.request(ctx, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {f.parentToken}, "actor_token": {f.childKey}, "resource": {resource}, "scope": {scope}})
}

func (f oauthDelegationFixture) assertNoDelegation(t *testing.T) {
	t.Helper()
	var events int
	var used *time.Time
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM audit_logs WHERE action = 'agent.token.exchange'),
		(SELECT last_used_at FROM agent_credentials WHERE member_id = $1)`, f.child.ID).Scan(&events, &used); err != nil || events != 0 || used != nil {
		t.Fatalf("rejected delegation changed issuance or credential usage: events=%d error=%v", events, err)
	}
}

func TestOAuthDelegationHTTPKeepsSaaSAudienceScopeAndAudit(t *testing.T) {
	for _, scope := range []string{"auth.members:read", ""} {
		name := "ExplicitScope"
		if scope == "" {
			name = "OmittedScope"
		}
		t.Run(name, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx := context.Background()
			out := f.exchange(ctx, "app_redemption", scope)
			token := delegationAuditToken(t, out)
			var response struct {
				Scope string `json:"scope"`
			}
			if json.Unmarshal(out.Body.Bytes(), &response) != nil || response.Scope != "auth.members:read" {
				t.Fatal("delegation response did not identify the issued scope")
			}
			claims, err := f.sessions.Signer.Verify(token, time.Now(), "app_redemption")
			if err != nil || claims.Type != "agent" || claims.Subject != f.child.ID || claims.MemberID != f.child.ID ||
				claims.SpaceID != f.owner.SpaceID || len(claims.Scopes) != 1 || claims.Scopes[0] != "auth.members:read" {
				t.Fatal("delegated token lost its SaaS audience, child identity, or scope restriction")
			}
			parent, err := f.sessions.Signer.Verify(f.parentToken, time.Now(), "app_redemption")
			if err != nil || claims.ExpiresAt > parent.ExpiresAt || claims.Actor == nil || claims.Actor.Subject != f.agent.ID ||
				claims.Actor.Actor == nil || claims.Actor.Actor.Subject != f.owner.ID {
				t.Fatal("delegated token exceeded its parent lifetime or lost its owner chain")
			}
			if _, active, err := f.sessions.Introspect(ctx, token, security.DefaultApplicationAudience); err != nil || active {
				t.Fatal("SaaS delegated token authenticated to Auth")
			}
			if _, active, err := f.sessions.Introspect(ctx, token, "app_other"); err != nil || active {
				t.Fatal("SaaS delegated token authenticated to another application")
			}
			page, err := f.applications.Authorization.ListAuditLogs(ctx, f.owner.ID,
				authorization.AuditQuery{SpaceID: f.owner.SpaceID, Action: "agent.token.exchange", MemberID: f.agent.ID})
			if err != nil || len(page.Events) != 1 {
				t.Fatal("OAuth delegation did not produce a queryable audit event")
			}
			event := page.Events[0]
			if event.ActorID != f.agent.ID || event.MemberID != f.child.ID || event.ApplicationID != "app_redemption" ||
				event.Plane != "principal" || event.CredentialType != "agent_token_exchange" || event.ResourceGroupID != f.child.HomeGroupID ||
				len(event.OwnerChain) != 2 || event.OwnerChain[0].MemberID != f.agent.ID || event.OwnerChain[1].MemberID != f.owner.ID {
				t.Fatal("delegation audit lost the authenticated application, parent, child, or owner chain")
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{f.parentToken, f.childKey, token, f.code, f.refresh} {
				if strings.Contains(string(encoded), private) {
					t.Fatal("delegation audit exposed a credential")
				}
			}
		})
	}
}

func TestOAuthDelegationHTTPDerivesOmittedScopeFromCurrentIntersection(t *testing.T) {
	for _, scenario := range []string{"Omitted", "ExplicitUnavailable", "ParentTokenRestriction"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx := context.Background()
			if _, err := f.store.Pool.Exec(ctx, `UPDATE applications SET allowed_scopes = '["auth.members:read","auth.roles:read"]' WHERE id = 'app_redemption';
				UPDATE application_installations SET approved_permissions = '["auth.members:read","auth.roles:read"]' WHERE id = 'ins_redemption'`); err != nil {
				t.Fatal(err)
			}
			scope := ""
			if scenario == "ExplicitUnavailable" {
				scope = "auth.members:read auth.roles:read"
			}
			if scenario == "ParentTokenRestriction" {
				claims, err := f.sessions.Signer.Verify(f.parentToken, time.Now(), "app_redemption")
				if err != nil {
					t.Fatal(err)
				}
				claims.Scopes = []string{"auth.roles:read"}
				f.parentToken, err = f.sessions.Signer.Sign(claims)
				if err != nil {
					t.Fatal(err)
				}
			}
			out := f.exchange(ctx, "app_redemption", scope)
			if scenario != "Omitted" {
				if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_scope") {
					t.Fatalf("delegation exceeded the parent or child scope: status=%d", out.Code)
				}
				f.assertNoDelegation(t)
				return
			}
			token := delegationAuditToken(t, out)
			claims, err := f.sessions.Signer.Verify(token, time.Now(), "app_redemption")
			if err != nil || len(claims.Scopes) != 1 || claims.Scopes[0] != "auth.members:read" {
				t.Fatal("omitted scope became unrestricted or included unavailable authority")
			}
		})
	}
}

func TestOAuthDelegationHTTPRechecksLifecycleAndExpiryAfterWaiting(t *testing.T) {
	for _, change := range []string{"Application", "Manifest", "Installation", "ParentEpoch", "ParentGrant", "Expiry"} {
		t.Run(change, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			expiresAt := time.Now().UTC().Add(2 * time.Second)
			if change == "Expiry" {
				claims, err := f.sessions.Signer.Verify(f.parentToken, time.Now(), "app_redemption")
				if err != nil {
					t.Fatal(err)
				}
				claims.ExpiresAt = expiresAt.Unix()
				f.parentToken, err = f.sessions.Signer.Sign(claims)
				if err != nil {
					t.Fatal(err)
				}
			}
			mutation, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mutation.Rollback(context.Background()) })
			if err := f.store.InTx(mutation.Context(ctx), func(q *db.Queries) error {
				if change == "ParentEpoch" || change == "ParentGrant" {
					if err := member.LockChainsTx(ctx, q, f.child.ID); err != nil {
						return err
					}
				} else if _, err := f.applications.OAuthClientByIDTx(ctx, q, "app_redemption"); err != nil {
					return err
				}
				tx, _ := q.Transaction()
				switch change {
				case "Application":
					return q.SuspendApplicationGlobally(ctx, db.SuspendApplicationGloballyParams{ApplicationID: "app_redemption"})
				case "Manifest":
					_, err := tx.Exec(ctx, `UPDATE applications SET allowed_scopes = '[]' WHERE id = 'app_redemption'`)
					return err
				case "Installation":
					_, err := tx.Exec(ctx, `UPDATE application_installations SET status = 'suspended' WHERE id = 'ins_redemption'`)
					return err
				case "ParentEpoch":
					if err := q.StopAgentMember(ctx, db.StopAgentMemberParams{MemberID: f.agent.ID}); err != nil {
						return err
					}
					return q.ResumeSuspendedAgent(ctx, db.ResumeSuspendedAgentParams{MemberID: f.agent.ID})
				case "ParentGrant":
					_, err := tx.Exec(ctx, `UPDATE authorization_grants SET revoked_at = now() WHERE id = $1`, "grt_"+f.agent.ID)
					return err
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() { response <- f.exchange(ctx, "app_redemption", "auth.members:read") }()
			waitForRedemptionLock(t, ctx, f.store, response)
			if change == "Expiry" {
				timer := time.NewTimer(time.Until(expiresAt.Add(25 * time.Millisecond)))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err := mutation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			out := <-response
			code := "invalid_grant"
			if change == "Manifest" || change == "ParentGrant" {
				code = "invalid_scope"
			}
			if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), code) {
				t.Fatalf("delegation ignored committed %s change: status=%d", change, out.Code)
			}
			f.assertNoDelegation(t)
		})
	}
}

func TestOAuthDelegationHTTPRollsBackSigningAuditAndCommitFailures(t *testing.T) {
	for _, failure := range []string{"Settings", "Audit", "Commit"} {
		t.Run(failure, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx := context.Background()
			settings := f.sessions.Settings
			if failure == "Settings" {
				f.sessions.Settings = func(context.Context) (session.Settings, error) {
					return session.Settings{}, errors.New("injected signing settings failure")
				}
			} else {
				if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_oauth_delegation() RETURNS trigger LANGUAGE plpgsql AS $$
					BEGIN IF NEW.action = 'agent.token.exchange' THEN RAISE EXCEPTION 'injected delegation audit failure'; END IF; RETURN NEW; END $$`); err != nil {
					t.Fatal(err)
				}
				trigger := `CREATE TRIGGER reject_oauth_delegation BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_oauth_delegation()`
				if failure == "Commit" {
					trigger = `CREATE CONSTRAINT TRIGGER reject_oauth_delegation AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_oauth_delegation()`
				}
				if _, err := f.store.Pool.Exec(ctx, trigger); err != nil {
					t.Fatal(err)
				}
			}
			out := f.exchange(ctx, "app_redemption", "auth.members:read")
			if out.Code != http.StatusServiceUnavailable || !strings.Contains(out.Body.String(), "temporarily_unavailable") || strings.Contains(out.Body.String(), "access_token") {
				t.Fatalf("delegation returned credentials on %s failure: status=%d", failure, out.Code)
			}
			f.assertNoDelegation(t)
			f.sessions.Settings = settings
			if failure != "Settings" {
				if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_oauth_delegation ON audit_logs`); err != nil {
					t.Fatal(err)
				}
			}
			delegationAuditToken(t, f.exchange(ctx, "app_redemption", "auth.members:read"))
		})
	}
}

func TestOAuthDelegationHTTPKeepsApplicationAndInstallationLocksUntilCommit(t *testing.T) {
	for _, change := range []string{"Application", "Installation"} {
		t.Run(change, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			issuance, err := f.store.BeginIdempotency(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = issuance.Rollback(context.Background()) })
			delegationAuditToken(t, f.exchange(issuance.Context(ctx), "app_redemption", "auth.members:read"))
			changed := make(chan error, 1)
			go func() {
				changed <- f.store.InTx(ctx, func(q *db.Queries) error {
					if change == "Application" {
						return q.SuspendApplicationGlobally(ctx, db.SuspendApplicationGloballyParams{ApplicationID: "app_redemption"})
					}
					// Exercise the installation row itself, independently of
					// lifecycle entry points that first lock the application.
					tx, _ := q.Transaction()
					_, err := tx.Exec(ctx, `UPDATE application_installations SET status = 'suspended' WHERE id = 'ins_redemption'`)
					return err
				})
			}()
			for {
				var waiting bool
				if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-changed:
					t.Fatalf("%s change bypassed uncommitted delegation: %v", change, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if err := issuance.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-changed; err != nil {
				t.Fatal(err)
			}
			out := f.exchange(ctx, "app_redemption", "auth.members:read")
			if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_grant") {
				t.Fatalf("subsequent delegation ignored %s change: status=%d", change, out.Code)
			}
			var events int
			if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'agent.token.exchange'`).Scan(&events); err != nil || events != 1 {
				t.Fatal("serialized lifecycle change lost or duplicated the committed delegation")
			}
		})
	}
}

func TestOAuthDelegationHTTPNestedChainRevocationAcrossInstances(t *testing.T) {
	f := newOAuthDelegationFixture(t)
	ctx := context.Background()
	childToken := delegationAuditToken(t, f.exchange(ctx, "app_redemption", "auth.members:read"))
	grandchild, grandchildKey, err := f.agents.Create(ctx, agent.CreateInput{
		OwnerMemberID: f.child.ID, Name: "nested reader", Source: "delegation", ExpiresAt: f.child.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ($1, $2, '["auth.members:read"]', $3, 'space', $2, $4)`, "grt_"+grandchild.ID, f.owner.SpaceID, grandchild.ID, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	nested := f
	nested.parentToken, nested.childKey = childToken, grandchildKey
	grandchildToken := delegationAuditToken(t, nested.exchange(ctx, "app_redemption", ""))
	claims, err := f.sessions.Signer.Verify(grandchildToken, time.Now(), "app_redemption")
	if err != nil || claims.Subject != grandchild.ID || claims.Actor == nil || claims.Actor.Subject != f.child.ID ||
		claims.Actor.Actor == nil || claims.Actor.Actor.Subject != f.agent.ID ||
		claims.Actor.Actor.Actor == nil || claims.Actor.Actor.Actor.Subject != f.owner.ID {
		t.Fatal("nested OAuth delegation lost the persisted complete ownership chain")
	}
	other, err := store.Open(ctx, f.store.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	otherSessions := &session.Service{Store: other, Signer: f.sessions.Signer, Settings: f.sessions.Settings}
	otherAgents := &agent.Service{Store: other, HMACKeys: f.agents.HMACKeys}
	otherAuthorization := &authorization.Service{Store: other}
	otherApplications := &application.Service{Store: other, Authorization: otherAuthorization, HMACKeys: f.applications.HMACKeys}
	var mux http.ServeMux
	(HTTP{Issuer: f.sessions.Signer.Issuer(), Applications: otherApplications, Agents: otherAgents,
		Sessions: otherSessions, Authorization: otherAuthorization}).Register(&mux)
	for _, token := range []string{f.parentToken, childToken, grandchildToken} {
		if _, active, err := otherSessions.Introspect(ctx, token, "app_redemption"); err != nil || !active {
			t.Fatal("second instance did not recognize an active delegated identity")
		}
	}
	sibling, siblingKey, err := f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "independent", ExpiresAt: f.agent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	siblingToken := delegationAuditToken(t, f.request(ctx, url.Values{"grant_type": {"agent_key"}, "agent_key": {siblingKey}, "resource": {"app_redemption"}}))
	revoke := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{"token": {f.refresh}}.Encode()))
	revoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, revoke)
	if out.Code != http.StatusOK {
		t.Fatalf("OAuth root revocation failed: status=%d", out.Code)
	}
	for _, token := range []string{f.parentToken, childToken, grandchildToken} {
		if _, active, err := otherSessions.Introspect(ctx, token, "app_redemption"); err != nil || active {
			t.Fatal("second instance retained an identity revoked through the OAuth root")
		}
	}
	if identity, active, err := otherSessions.Introspect(ctx, siblingToken, "app_redemption"); err != nil || !active || identity.Subject != sibling.ID {
		t.Fatal("OAuth revocation invalidated an independent sibling")
	}
	nested.handler = &mux
	if out := nested.exchange(ctx, "app_redemption", "auth.members:read"); out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_grant") {
		t.Fatalf("revoked descendant exchanged another token on the second instance: status=%d", out.Code)
	}
	page, err := otherAuthorization.ListAuditLogs(ctx, f.owner.ID,
		authorization.AuditQuery{SpaceID: f.owner.SpaceID, Action: "agent.token.exchange", MemberID: f.agent.ID})
	if err != nil || len(page.Events) != 2 {
		t.Fatal("OAuth root revocation lost the two committed delegation audit snapshots")
	}
}

func TestOAuthRevokeSaaSAccessTokenDisablesDelegatedAuthorization(t *testing.T) {
	f := newOAuthDelegationFixture(t)
	ctx := context.Background()
	childToken := delegationAuditToken(t, f.exchange(ctx, "app_redemption", "auth.members:read"))
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{"token": {f.parentToken}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("OAuth access token revocation failed: status=%d", out.Code)
	}
	for _, token := range []string{f.parentToken, childToken} {
		if _, active, err := f.sessions.Introspect(ctx, token, "app_redemption"); err != nil || active {
			t.Fatal("successful SaaS access token revocation left its delegated authorization active")
		}
	}
}

func TestOAuthDelegationHTTPRejectsAudienceAndAuthorityEscalation(t *testing.T) {
	for _, scenario := range []string{"AuthAudience", "OtherAudience", "MissingAudience", "Manifest", "InstallationPermissions", "InstallationInactive", "ClientInactive", "ParentClient", "ParentGrant", "ChildGrant", "ApprovalRequired"} {
		t.Run(scenario, func(t *testing.T) {
			f := newOAuthDelegationFixture(t)
			ctx := context.Background()
			resource, scope, code := "app_redemption", "auth.members:read", "invalid_scope"
			var statement string
			var args []any
			switch scenario {
			case "AuthAudience":
				resource, code = security.DefaultApplicationAudience, "invalid_grant"
			case "OtherAudience":
				resource, code = "app_other", "invalid_grant"
			case "MissingAudience":
				resource, code = "", "invalid_grant"
			case "Manifest":
				statement = `UPDATE applications SET allowed_scopes = '[]' WHERE id = 'app_redemption'`
			case "InstallationPermissions":
				statement = `UPDATE application_installations SET approved_permissions = '[]' WHERE id = 'ins_redemption'`
			case "InstallationInactive":
				statement, code = `UPDATE application_installations SET status = 'suspended' WHERE id = 'ins_redemption'`, "invalid_grant"
			case "ClientInactive":
				statement, code = `UPDATE applications SET status = 'suspended' WHERE id = 'app_redemption'`, "invalid_grant"
			case "ParentClient":
				statement, args, code = `UPDATE members SET oauth_client_id = 'app_other' WHERE id = $1`, []any{f.agent.ID}, "invalid_grant"
			case "ParentGrant":
				statement, args = `UPDATE authorization_grants SET revoked_at = now() WHERE id = $1`, []any{"grt_" + f.agent.ID}
			case "ChildGrant":
				statement, args = `UPDATE authorization_grants SET revoked_at = now() WHERE id = $1`, []any{"grt_" + f.child.ID}
			case "ApprovalRequired":
				statement = `UPDATE permissions SET agent_approval = 'required' WHERE key = 'auth.members:read'`
			}
			if statement != "" {
				if _, err := f.store.Pool.Exec(ctx, statement, args...); err != nil {
					t.Fatal(err)
				}
			}
			out := f.exchange(ctx, resource, scope)
			if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), code) || strings.Contains(out.Body.String(), "access_token") {
				t.Fatalf("delegation bypassed %s: status=%d", scenario, out.Code)
			}
			f.assertNoDelegation(t)
		})
	}
}
