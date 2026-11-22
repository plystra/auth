package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/enterprise"
	"github.com/plystra/auth/internal/store"
)

type jitMappingFixture struct {
	st                               *store.Store
	svc                              *enterprise.Service
	provider                         *oidcTestProvider
	space, owner, configurator, role string
	connection                       enterprise.Connection
}

func newJITMappingFixture(t *testing.T, agentConfigurator bool) *jitMappingFixture {
	t.Helper()
	ctx := context.Background()
	st, az, svc, owner, space, provider := newSSOHTTPFixture(t)
	role, err := az.CreateRole(ctx, owner.ID, space, "Mapped role", "", []string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}
	f := &jitMappingFixture{st: st, svc: svc, provider: provider, owner: owner.ID, space: space, configurator: owner.ID, role: role.ID}
	caller := authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner")
	if agentConfigurator {
		actor, _, err := (&agent.Service{Store: st}).Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, CreatedByUser: "usr_sso_http_owner", Name: "SSO configurator"})
		if err != nil {
			t.Fatal(err)
		}
		f.configurator = actor.ID
		f.exec(t, `UPDATE permissions SET agent_approval='none' WHERE key='auth.connections:manage';
			INSERT INTO authorization_grants (id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
			VALUES ('grt_jit_manager',@space,'["auth.connections:manage","auth.grants:assign"]',@actor,'space',@space,@owner)`)
		if _, err := az.CreateAssignmentRight(ctx, owner.ID, space, actor.ID, []string{"auth.members:read"}, space, "", false, false, nil); err != nil {
			t.Fatal(err)
		}
		caller = ctx
	}
	f.connection, err = svc.CreateConnection(caller, f.configurator, space, ssoMappingInput(provider.issuer, role.ID))
	if err != nil {
		t.Fatal(err)
	}
	row, err := st.Queries().GetSSOConnection(ctx, db.GetSSOConnectionParams{ID: f.connection.ID})
	if err != nil || row.ConfiguredByMemberID.String != f.configurator || row.ConfiguredByUserID.Valid == agentConfigurator ||
		!agentConfigurator && row.ConfiguredByUserID.String != "usr_sso_http_owner" {
		t.Fatalf("connection did not retain its verified configurator: %v", err)
	}
	return f
}

func (f *jitMappingFixture) exec(t *testing.T, query string) {
	t.Helper()
	_, err := f.st.Pool.Exec(context.Background(), query, pgx.QueryExecModeSimpleProtocol,
		pgx.NamedArgs{"space": f.space, "owner": f.owner, "actor": f.configurator, "connection": f.connection.ID, "role": f.role})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *jitMappingFixture) start(t *testing.T, subject string, groups ...string) enterprise.CallbackInput {
	t.Helper()
	start, err := f.svc.Start(context.Background(), f.connection.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	f.provider.addCode(start.State, oidcTestCode{nonce: target.Query().Get("nonce"), subject: subject, email: subject + "@example.test", emailVerified: true, groups: groups})
	return enterprise.CallbackInput{ConnectionID: f.connection.ID, State: start.State, Code: start.State}
}

func (f *jitMappingFixture) login(t *testing.T, subject string, groups ...string) string {
	t.Helper()
	result, err := f.svc.Callback(context.Background(), f.start(t, subject, groups...))
	if err != nil || result.Tokens == nil {
		t.Fatalf("SSO callback failed to create a session: %v", err)
	}
	claims, err := f.svc.Sessions.VerifyAccess(result.Tokens.AccessToken)
	if err != nil || claims.MemberID == "" {
		t.Fatalf("SSO callback did not issue a member token: %v", err)
	}
	return claims.MemberID
}

func (f *jitMappingFixture) grantCount(t *testing.T, member string) int {
	t.Helper()
	var count int
	if err := f.st.Pool.QueryRow(context.Background(), "SELECT count(*) FROM authorization_grants WHERE role_id=$1 AND grantee_member_id=$2 AND revoked_at IS NULL", f.role, member).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// Include the single-use state and all persisted JIT effects. The signed IdP
// exchange happens before this transaction and creates no local principal.
func (f *jitMappingFixture) counts(t *testing.T) [8]int {
	t.Helper()
	var v [8]int
	err := f.st.Pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM users), (SELECT count(*) FROM members),
		(SELECT count(*) FROM user_members), (SELECT count(*) FROM external_identities),
		(SELECT count(*) FROM authorization_grants), (SELECT count(*) FROM sessions),
		(SELECT count(*) FROM audit_logs WHERE action='auth.sso.login' AND outcome='success'),
		(SELECT count(*) FROM sso_states WHERE consumed_at IS NOT NULL)`).Scan(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7])
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *jitMappingFixture) assertDenied(t *testing.T, err error, want string, before [8]int) {
	t.Helper()
	var public *apierr.Error
	if !errors.As(err, &public) || public.Code != want {
		t.Fatalf("SSO callback error = %v, want %s", err, want)
	}
	if after := f.counts(t); after != before {
		t.Fatalf("denied callback committed side effects: before=%v after=%v", before, after)
	}
}

func TestSSOJITRechecksConfiguratorOnlyForNewMappedAuthority(t *testing.T) {
	f := newJITMappingFixture(t, false)
	first := f.login(t, "original", "engineering", "platform")
	if f.grantCount(t, first) != 1 {
		t.Fatal("first login did not grant the matched role exactly once")
	}
	f.exec(t, "UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=@owner")
	in := f.start(t, "denied", "engineering")
	before := f.counts(t)
	_, err := f.svc.Callback(context.Background(), in)
	f.assertDenied(t, err, "AUTHORITY_DELTA_NOT_COVERED", before)
	if returned := f.login(t, "original", "engineering"); returned != first || f.grantCount(t, first) != 1 {
		t.Fatal("returning member lost their binding or replayed the mapping")
	}
	if f.grantCount(t, f.login(t, "unmatched", "support")) != 0 {
		t.Fatal("unmatched group gained a mapped role")
	}
}

func TestSSOJITRequiresVerifiedActiveHumanConfigurator(t *testing.T) {
	cases := []struct{ name, change, code string }{
		{"legacy mapping", "UPDATE sso_connections SET configured_by_user_id=NULL, configured_by_member_id=NULL WHERE id=@connection", "AUTHORITY_DELTA_NOT_COVERED"},
		{"missing user", "UPDATE sso_connections SET configured_by_user_id=NULL WHERE id=@connection", "AUTHORITY_DELTA_NOT_COVERED"},
		{"inactive account", "UPDATE users SET status='disabled' WHERE id='usr_sso_http_owner'", "UNAUTHENTICATED"},
		{"inactive member", "UPDATE members SET status='suspended' WHERE id=@owner", "AUTHORITY_DELTA_NOT_COVERED"},
		{"revoked shared binding", `UPDATE members SET binding_policy='shared' WHERE id=@owner;
			INSERT INTO users (id,email,email_normalized,password_hash,status) VALUES ('usr_jit_other','other@example.test','other@example.test','unused','active');
			INSERT INTO user_members (user_id,member_id) VALUES ('usr_jit_other',@owner);
			UPDATE user_members SET status='revoked',revoked_at=now() WHERE user_id='usr_sso_http_owner' AND member_id=@owner`, "UNAUTHENTICATED"},
		{"assignment permission disabled", "UPDATE permissions SET status='disabled' WHERE key='auth.grants:assign'", "PERMISSION_DISABLED"},
		{"delegate envelope removed", `INSERT INTO space_envelopes (space_id) VALUES (@space);
			INSERT INTO space_envelope_entries (space_id,permission_id,mode) SELECT @space,id,
			CASE WHEN key='auth.members:read' THEN 'use' ELSE 'delegate' END FROM permissions WHERE delegable`, "AUTHORITY_DELTA_NOT_COVERED"},
		{"role gained uncovered permission", `UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=@owner;
			INSERT INTO assign_rights(id,holder_member_id,permission_keys,anchor_space_id,source) VALUES ('ar_jit_reader',@owner,'["auth.members:read"]',@space,'system');
			INSERT INTO role_permissions(role_id,permission_id) SELECT @role,id FROM permissions WHERE key='auth.roles:manage'`, "AUTHORITY_DELTA_NOT_COVERED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newJITMappingFixture(t, false)
			f.exec(t, tc.change)
			in := f.start(t, "new-identity", "engineering")
			before := f.counts(t)
			_, err := f.svc.Callback(context.Background(), in)
			f.assertDenied(t, err, tc.code, before)
		})
	}
}

func TestSSOJITEmptyDeltaSupportsHistoricalConnection(t *testing.T) {
	f := newJITMappingFixture(t, false)
	f.exec(t, `UPDATE sso_connections SET configured_by_user_id=NULL,configured_by_member_id=NULL WHERE id=@connection;
		INSERT INTO role_permissions (role_id,permission_id) SELECT r.id,p.id FROM roles r, permissions p
		WHERE r.space_id=@space AND r.name='member' AND p.key='auth.members:read'`)
	if f.grantCount(t, f.login(t, "covered-by-default", "engineering")) != 1 {
		t.Fatal("default-equivalent matched role was not recorded")
	}
}

func TestSSOJITUsesCurrentAgentOwnerAndCannotReplayApproval(t *testing.T) {
	f := newJITMappingFixture(t, true)
	f.exec(t, "UPDATE permissions SET agent_approval='required' WHERE key='auth.connections:manage'")
	if f.grantCount(t, f.login(t, "covered-by-agent", "engineering")) != 1 {
		t.Fatal("first login did not use the Agent's covered authority")
	}
	for _, tc := range []struct{ name, change, code string }{
		{"approval for assignment", "UPDATE permissions SET agent_approval='required' WHERE key='auth.grants:assign'", "APPROVAL_REQUIRED"},
		{"owner lost assignment right", `UPDATE permissions SET agent_approval='none' WHERE key='auth.grants:assign';
			UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=@owner`, "AUTHORITY_DELTA_NOT_COVERED"},
		{"inactive owner", "UPDATE members SET status='suspended' WHERE id=@owner", "OWNER_INACTIVE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.exec(t, tc.change)
			in := f.start(t, "new-agent-target", "engineering")
			before := f.counts(t)
			_, err := f.svc.Callback(context.Background(), in)
			f.assertDenied(t, err, tc.code, before)
		})
	}
}

func TestSSOJITSAMLCallbackRejectsRevokedMappingAuthority(t *testing.T) {
	ctx := t.Context()
	st, az, svc, owner, space, _ := newSSOHTTPFixture(t)
	svc.Issuer = "https://auth.test"
	role, err := az.CreateRole(ctx, owner.ID, space, "SAML mapping", "", []string{"auth.members:read"})
	if err != nil {
		t.Fatal(err)
	}
	metadata, signing := newSAMLTestIssuer(t)
	connection, err := svc.CreateConnection(authorization.WithHumanActor(ctx, owner.ID, "usr_sso_http_owner"), owner.ID, space, enterprise.ConnectionInput{
		Name: "Workforce", Provider: "saml", RedirectURI: svc.Issuer + "/v1/sso/{connection_id}/callback",
		SAMLMetadata: metadata, RoleMappings: map[string]string{"engineering": role.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	start, err := svc.Start(ctx, connection.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	var requestID string
	if err := st.Pool.QueryRow(ctx, "SELECT request_id FROM sso_states WHERE connection_id=$1", connection.ID).Scan(&requestID); err != nil {
		t.Fatal(err)
	}
	assertion := signedSAMLTestResponse(t, signing, connection, requestID, "new-saml-subject", []samlTestAttribute{{name: "groups", value: "engineering"}}, false)
	f := &jitMappingFixture{st: st, owner: owner.ID}
	f.exec(t, "UPDATE assign_rights SET revoked_at=now() WHERE holder_member_id=@owner")
	before := f.counts(t)
	mux := http.NewServeMux()
	(HTTP{Enterprise: svc}).Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	res, err := server.Client().PostForm(server.URL+"/v1/sso/"+connection.ID+"/callback", url.Values{"RelayState": {start.State}, "SAMLResponse": {assertion}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var body struct{ Error struct{ Code string } }
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusForbidden || body.Error.Code != "AUTHORITY_DELTA_NOT_COVERED" || before != f.counts(t) {
		t.Fatalf("signed SAML mapping after revocation: status=%d code=%q", res.StatusCode, body.Error.Code)
	}
}

func TestSSOJITWaitsForConcurrentAssignmentRevocation(t *testing.T) {
	f := newJITMappingFixture(t, false)
	in := f.start(t, "concurrent-target", "engineering")
	before := f.counts(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var rightID string
	if err := f.st.Pool.QueryRow(ctx, "SELECT id FROM assign_rights WHERE holder_member_id=$1 AND revoked_at IS NULL", f.owner).Scan(&rightID); err != nil {
		t.Fatal(err)
	}
	edit, err := f.st.BeginIdempotency(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = edit.Rollback(context.Background()) }()
	if err := f.st.InTx(edit.Context(ctx), func(q *db.Queries) error {
		if _, err := q.LockMemberForAuthorization(ctx, db.LockMemberForAuthorizationParams{ID: f.owner}); err != nil {
			return err
		}
		return q.RevokeAssignRight(ctx, db.RevokeAssignRightParams{ID: rightID})
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.svc.Callback(ctx, in)
		done <- err
	}()
	for {
		select {
		case err := <-done:
			t.Fatalf("callback completed before revocation: %v", err)
		default:
		}
		var waiting bool
		if err := f.st.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%LockMemberForAuthorization%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := edit.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.assertDenied(t, <-done, "AUTHORITY_DELTA_NOT_COVERED", before)
}
