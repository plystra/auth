package operator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
	"github.com/plystra/auth/internal/factor"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type applicationSuspensionFixture struct {
	store         *store.Store
	operators     *Service
	agents        *agent.Service
	applications  *application.Service
	authorizers   []*authorization.Service
	sessions      *session.Service
	application   application.PublishedApplication
	owners        []authorization.Member
	installations []application.Installation
	agentMembers  []agent.Agent
	keys          []string
	tokens        []string
	refresh       []string
	control       agent.Agent
	controlKey    string
	operatorToken string
	digest        [sha256.Size]byte
}

func newApplicationSuspensionFixture(t *testing.T) *applicationSuspensionFixture {
	t.Helper()
	ctx := context.Background()
	st := newOperatorStore(t)
	key := []byte(strings.Repeat("s", 32))
	f := &applicationSuspensionFixture{
		store: st, agents: &agent.Service{Store: st, HMACKeys: [][]byte{key}},
		operators: &Service{Store: st, HMACKeys: [][]byte{key}, Factors: &factor.Service{Store: st, DataKey: secret.New(strings.Repeat("d", 32))}},
	}
	otherStore, err := store.Open(ctx, st.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherStore.Close)
	f.authorizers = []*authorization.Service{{Store: st}, {Store: otherStore}}
	f.applications = &application.Service{Store: st, HMACKeys: [][]byte{key}, Authorization: f.authorizers[0]}
	insertOperator(t, st, "usr_stop_operator", "stop-operator", `["*"]`)
	f.operatorToken = insertOperatorSession(t, st, "usr_stop_operator", key, nil)
	for i := range 2 {
		userID := fmt.Sprintf("usr_stop_owner_%d", i)
		if err := insertAccountUserForOperator(ctx, st, userID, fmt.Sprintf("stop-owner-%d@example.test", i), "active"); err != nil {
			t.Fatal(err)
		}
		_, owner, err := f.authorizers[0].CreateSpace(ctx, userID, fmt.Sprintf("Customer %d", i), fmt.Sprintf("stop-customer-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		f.owners = append(f.owners, owner)
		if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
			(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
			VALUES ($1, $2, '["auth.applications:manage","auth.agents:create"]'::jsonb, $3, 'space', $2, 'system')`, "grt_"+owner.ID, owner.SpaceID, owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	f.application, err = f.applications.Register(ctx, f.owners[0].ID, application.RegisterInput{
		SpaceID: f.owners[0].SpaceID, Name: "Global stop client", Visibility: "public",
		RedirectURIs:        []string{"https://saas.example.test/callback"},
		ManifestPermissions: []string{"auth.agents:create", "auth.authz:check", "auth.tokens:introspect"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.application.ClientID = "https://client.example.test/metadata.json"
	if _, err := st.Pool.Exec(ctx, `UPDATE applications SET review_status = 'approved',
		manifest_permissions = pending_manifest_permissions, allowed_scopes = pending_manifest_permissions,
		pending_manifest_permissions = NULL, client_id = $2 WHERE id = $1`, f.application.ID, f.application.ClientID); err != nil {
		t.Fatal(err)
	}
	f.digest = sha256.Sum256([]byte(fmt.Sprintf(`{"application_id":%q}`, f.application.ID)))
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	for _, owner := range f.owners {
		installation, err := f.applications.InstallSpace(ctx, owner.ID, f.application.ID, owner.SpaceID)
		if err != nil {
			t.Fatal(err)
		}
		f.installations = append(f.installations, installation)
		root, err := f.agents.CreateOAuth(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "OAuth root", Source: "oauth", OAuthClientID: f.application.ClientID, ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		refresh, err := f.agents.CreateOAuthRefreshCredential(ctx, root.ID, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		f.refresh = append(f.refresh, refresh)
		f.addAgent(t, root, "")
		for _, parent := range []string{root.ID, installation.MemberID} {
			child, raw, err := f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent, Name: "Delegated worker", Source: "delegation", ExpiresAt: expires})
			if err != nil {
				t.Fatal(err)
			}
			f.addAgent(t, child, raw)
			grandchild, raw, err := f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: child.ID, Name: "Nested worker", Source: "delegation", ExpiresAt: expires})
			if err != nil {
				t.Fatal(err)
			}
			f.addAgent(t, grandchild, raw)
		}
	}
	f.control, f.controlKey, err = f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.owners[0].ID, Name: "Independent sibling"})
	if err != nil {
		t.Fatal(err)
	}
	f.grant(t, f.control)
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	f.sessions = &session.Service{Store: otherStore, Signer: signer, HMACKeys: [][]byte{key}, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: time.Hour}, nil
	}}
	for _, member := range f.agentMembers {
		tokens, err := f.sessions.CreateAgentAccess(ctx, member.ID, member.SpaceID, security.DefaultApplicationAudience)
		if err != nil {
			t.Fatal(err)
		}
		f.tokens = append(f.tokens, tokens.AccessToken)
	}
	f.stepUp(t)
	return f
}

func (f *applicationSuspensionFixture) grant(t *testing.T, member agent.Agent) {
	t.Helper()
	if _, err := f.store.Pool.Exec(context.Background(), `INSERT INTO authorization_grants
		(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
		VALUES ($1, $2, '["auth.agents:create"]'::jsonb, $3, 'space', $2, 'system')`, "grt_"+member.ID, member.SpaceID, member.ID); err != nil {
		t.Fatal(err)
	}
}

func (f *applicationSuspensionFixture) addAgent(t *testing.T, member agent.Agent, key string) {
	t.Helper()
	f.grant(t, member)
	f.agentMembers, f.keys = append(f.agentMembers, member), append(f.keys, key)
}

func (f *applicationSuspensionFixture) stepUp(t *testing.T) {
	t.Helper()
	if _, err := f.store.Pool.Exec(context.Background(), `UPDATE operator_sessions SET step_up_operation = 'ops.applications.suspend',
		step_up_digest = $1, step_up_expires_at = now() + interval '5 minutes' WHERE user_id = 'usr_stop_operator'`, f.digest[:]); err != nil {
		t.Fatal(err)
	}
}

func (f *applicationSuspensionFixture) check(t *testing.T, allowed bool) {
	t.Helper()
	ctx := context.Background()
	for _, member := range append(append([]agent.Agent(nil), f.agentMembers...), f.control) {
		want := engine.Deny
		if allowed || member.ID == f.control.ID {
			want = engine.Allow
		}
		for _, authorizer := range f.authorizers {
			decision, _, err := authorizer.Check(ctx, authorization.CheckRequest{MemberID: member.ID, Permission: "auth.agents:create", ResourceSpace: member.SpaceID})
			if err != nil || decision.Effect != want {
				t.Fatalf("member %s: decision=%s code=%s error=%v, want=%s", member.ID, decision.Effect, decision.Code, err, want)
			}
		}
	}
	for i, token := range f.tokens {
		_, active, err := f.sessions.Introspect(ctx, token, security.DefaultApplicationAudience)
		if err != nil || active != allowed {
			t.Fatalf("token %d active=%t error=%v, want=%t", i, active, err, allowed)
		}
		if f.keys[i] != "" {
			_, err := f.agents.AuthenticateKey(ctx, f.keys[i])
			if (err == nil) != allowed {
				t.Fatalf("key %d validity=%t, want=%t", i, err == nil, allowed)
			}
		}
	}
	if _, err := f.agents.AuthenticateKey(ctx, f.controlKey); err != nil {
		t.Fatalf("independent sibling credential became invalid: %v", err)
	}
}

func TestGlobalApplicationSuspensionRevokesEveryCustomerDelegation(t *testing.T) {
	f := newApplicationSuspensionFixture(t)
	ctx := context.Background()
	f.check(t, true) // Warm both independent authorization caches.
	if err := f.operators.SuspendApplication(ctx, f.operatorToken, f.application.ID, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	f.check(t, false)
	for _, refresh := range f.refresh {
		if _, _, err := f.agents.RotateOAuthRefresh(ctx, refresh); err == nil {
			t.Fatal("a stopped OAuth refresh credential remained usable")
		}
	}
	// Each customer administrator retains ordinary governance authority, but
	// cannot locally reactivate an identity stopped by the deployment operator.
	for i, owner := range f.owners {
		assertOperatorError(t, f.authorizers[0].SetMemberStatus(ctx, owner.ID, owner.SpaceID, f.installations[i].MemberID, "active"), "CONFLICT")
		assertOperatorError(t, f.authorizers[0].SetMemberStatus(ctx, owner.ID, owner.SpaceID, f.agentMembers[i*5].ID, "active"), "CONFLICT")
		assertOperatorError(t, f.authorizers[0].SetMemberStatus(ctx, owner.ID, owner.SpaceID, f.agentMembers[i*5+1].ID, "active"), "CONFLICT")
		assertOperatorError(t, f.authorizers[0].SetMemberStatus(ctx, owner.ID, owner.SpaceID, f.agentMembers[i*5+3].ID, "active"), "CONFLICT")
		_, err := f.agents.RotateForUser(ctx, owner.ID, fmt.Sprintf("usr_stop_owner_%d", i), f.agentMembers[i*5].ID)
		assertOperatorError(t, err, "CONFLICT")
	}
	var events, credentials int
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN
		('ops.application.agent.stop', 'ops.application.installation.suspend') AND application_id = $1
		AND user_id = 'usr_stop_operator' AND credential_type = 'operator_session'`, f.application.ID).Scan(&events); err != nil || events != 4 {
		t.Fatalf("customer-scoped suspension audit events=%d error=%v", events, err)
	}
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_credentials c JOIN members m ON m.id = c.member_id
		WHERE m.status = 'suspended' AND c.revoked_at IS NULL`).Scan(&credentials); err != nil || credentials != 0 {
		t.Fatalf("suspended identities retain %d credentials, error=%v", credentials, err)
	}
	var auditJSON string
	if err := f.store.Pool.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a))::text FROM audit_logs a
		WHERE a.action LIKE 'ops.application.%'`).Scan(&auditJSON); err != nil {
		t.Fatal(err)
	}
	for _, value := range append(append(append([]string{f.operatorToken, f.controlKey}, f.keys...), f.tokens...), f.refresh...) {
		if value != "" && strings.Contains(auditJSON, value) {
			t.Fatal("global suspension audit contains a credential")
		}
	}
	assertOperatorError(t, f.operators.SuspendApplication(ctx, f.operatorToken, f.application.ID, f.digest[:]), "STEP_UP_REQUIRED")
}

func TestGlobalApplicationSuspensionRollsBackAllEffectsWhenAuditFails(t *testing.T) {
	f := newApplicationSuspensionFixture(t)
	ctx := context.Background()
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION fail_global_stop_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'ops.application.suspend' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
		CREATE TRIGGER fail_global_stop_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION fail_global_stop_audit()`); err != nil {
		t.Fatal(err)
	}
	if err := f.operators.SuspendApplication(ctx, f.operatorToken, f.application.ID, f.digest[:]); err == nil {
		t.Fatal("suspension succeeded without durable audit")
	}
	f.check(t, true)
	client, err := f.applications.OAuthClient(ctx, f.application.ClientID)
	if err != nil || client.ID != f.application.ID {
		t.Fatal("failed suspension changed client activity")
	}
	var events int
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN
		('ops.application.agent.stop', 'ops.application.installation.suspend')`).Scan(&events); err != nil || events != 0 {
		t.Fatalf("failed suspension persisted %d success events, error=%v", events, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER fail_global_stop_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	// The failed transaction must also preserve the single-use step-up.
	if err := f.operators.SuspendApplication(ctx, f.operatorToken, f.application.ID, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	f.check(t, false)
}

func TestGlobalApplicationSuspensionSerializesWithChildCreation(t *testing.T) {
	f := newApplicationSuspensionFixture(t)
	ctx := context.Background()
	start := make(chan struct{})
	type creation struct {
		member agent.Agent
		err    error
	}
	results := make(chan creation, 16)
	var pending sync.WaitGroup
	for i := range 16 {
		pending.Go(func() {
			<-start
			ownerID := f.agentMembers[0].ID
			if i%2 == 0 {
				ownerID = f.installations[1].MemberID
			}
			created, _, err := f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: ownerID, Name: "Concurrent worker", ExpiresAt: f.agentMembers[0].ExpiresAt})
			results <- creation{created, err}
		})
	}
	close(start)
	if err := f.operators.SuspendApplication(ctx, f.operatorToken, f.application.ID, f.digest[:]); err != nil {
		t.Fatal(err)
	}
	pending.Wait()
	close(results)
	for result := range results {
		if result.err != nil {
			assertOperatorError(t, result.err, "OWNER_INACTIVE")
			continue
		}
		var active bool
		if err := f.store.Pool.QueryRow(ctx, `SELECT status = 'active' FROM members WHERE id = $1`, result.member.ID).Scan(&active); err != nil || active {
			t.Fatalf("concurrent child escaped global suspension: active=%t error=%v", active, err)
		}
	}
}
