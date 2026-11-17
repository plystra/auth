package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/member"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

type delegationAuditFixture struct {
	store               *store.Store
	authorization       *authorization.Service
	agents              *agent.Service
	sessions            *session.Service
	owner               authorization.Member
	parent, child       agent.Agent
	parentKey, childKey string
	parentToken         string
	handler             http.Handler
}

func newDelegationAuditFixture(t *testing.T) delegationAuditFixture {
	t.Helper()
	ctx := context.Background()
	database, err := protocolDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_delegation_audit', 'delegation-audit@example.test', 'delegation-audit@example.test', 'test-hash', 'active')`); err != nil {
		t.Fatal(err)
	}
	authz := &authorization.Service{Store: st}
	_, owner, err := authz.CreateSpace(ctx, "usr_delegation_audit", "Delegation audit", "delegation-audit")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st, HMACKeys: [][]byte{[]byte(strings.Repeat("a", 32))}}
	parent, parentKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: owner.ID, Name: "parent", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{parent.ID, child.ID} {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO authorization_grants
			(id, space_id, permission_keys, grantee_member_id, scope, anchor_space_id, granted_by)
			VALUES ($1, $2, '["auth.members:read"]', $3, 'space', $2, $4)`, "grt_"+id, owner.SpaceID, id, owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := &session.Service{Store: st, Signer: signer, Settings: func(context.Context) (session.Settings, error) {
		return session.Settings{AccessTTL: time.Minute}, nil
	}}
	var mux http.ServeMux
	(HTTP{Issuer: signer.Issuer(), Agents: agents, Sessions: sessions, Authorization: authz}).Register(&mux)
	f := delegationAuditFixture{store: st, authorization: authz, agents: agents, sessions: sessions,
		owner: owner, parent: parent, child: child, parentKey: parentKey, childKey: childKey,
		handler: route.Middleware(route.Principal, &mux)}
	response := f.request(ctx, false)
	f.parentToken = delegationAuditToken(t, response)
	return f
}

func (f delegationAuditFixture) request(ctx context.Context, delegated bool) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"agent_key"}, "agent_key": {f.parentKey}, "resource": {security.DefaultApplicationAudience}}
	if delegated {
		form = url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token": {f.parentToken}, "actor_token": {f.childKey}, "scope": {"auth.members:read"},
			"resource": {security.DefaultApplicationAudience}}
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode())).WithContext(ctx)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Request-ID", "req_delegation_audit")
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func delegationAuditToken(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.AccessToken == "" {
		t.Fatalf("token issuance failed: status=%d", response.Code)
	}
	return body.AccessToken
}

func TestAgentTokenIssuanceHTTPPersistsDelegationAuditSnapshots(t *testing.T) {
	f := newDelegationAuditFixture(t)
	ctx := context.Background()
	token := delegationAuditToken(t, f.request(ctx, true))
	claims, err := f.sessions.Signer.Verify(token, time.Now(), security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.authorization.ListAuditLogs(ctx, f.owner.ID, authorization.AuditQuery{SpaceID: f.owner.SpaceID, MemberID: f.parent.ID})
	if err != nil {
		t.Fatal(err)
	}
	var exchange audit.Event
	seenIssue := false
	for _, event := range page.Events {
		switch event.Action {
		case "agent.access.issue":
			seenIssue = event.ActorID == f.parent.ID && event.MemberID == f.parent.ID && event.CredentialType == "agent_key"
		case "agent.token.exchange":
			exchange = event
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{f.parentKey, f.childKey, f.parentToken, token} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("token issuance audit exposed a credential")
			}
		}
	}
	if !seenIssue || exchange.ID == "" || exchange.ActorID != f.parent.ID || exchange.MemberID != f.child.ID ||
		exchange.MemberType != "agent" || exchange.SpaceID != f.owner.SpaceID || exchange.ResourceGroupID != f.child.HomeGroupID ||
		exchange.Plane != "principal" || exchange.CredentialType != "agent_token_exchange" || exchange.RequestID != "req_delegation_audit" {
		t.Fatal("token issuance audit omitted the authenticated delegator, child or resource context")
	}
	if len(exchange.OwnerChain) != 2 || exchange.OwnerChain[0].MemberID != f.parent.ID || exchange.OwnerChain[1].MemberID != f.owner.ID ||
		claims.Actor == nil || claims.Actor.Subject != exchange.OwnerChain[0].MemberID || claims.Actor.Actor == nil || claims.Actor.Actor.Subject != exchange.OwnerChain[1].MemberID {
		t.Fatal("token and audit disagree about the complete delegation chain")
	}
	var metadata struct {
		ExpiresAt time.Time `json:"expires_at"`
		Complete  bool      `json:"owner_chain_complete"`
	}
	if json.Unmarshal(exchange.Metadata, &metadata) != nil || !metadata.Complete || metadata.ExpiresAt.Unix() != claims.ExpiresAt {
		t.Fatal("token issuance audit omitted the expiry or complete-chain marker")
	}
	if err := f.agents.Delete(ctx, f.parent.ID, f.child.ID); err != nil {
		t.Fatal(err)
	}
	page, err = f.authorization.ListAuditLogs(ctx, f.owner.ID, authorization.AuditQuery{SpaceID: f.owner.SpaceID, MemberID: f.parent.ID, Action: "agent.token.exchange"})
	if err != nil || len(page.Events) != 1 || page.Events[0].ID != exchange.ID {
		t.Fatal("delegation audit was lost after subtree removal")
	}
	before, _ := json.Marshal(exchange)
	after, _ := json.Marshal(page.Events[0])
	if !bytes.Equal(before, after) {
		t.Fatal("tombstone changed the historical token issuance snapshot")
	}
}

func TestAgentTokenIssuanceHTTPFailsClosedOnAuditFailure(t *testing.T) {
	f := newDelegationAuditFixture(t)
	ctx := context.Background()
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_token_issuance_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action IN ('agent.access.issue', 'agent.token.exchange') THEN RAISE EXCEPTION 'issuance audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_token_issuance_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_token_issuance_audit()`); err != nil {
		t.Fatal(err)
	}
	for _, delegated := range []bool{false, true} {
		response := f.request(ctx, delegated)
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "temporarily_unavailable") || strings.Contains(response.Body.String(), "access_token") {
			t.Fatalf("audit failure returned a token: delegated=%t status=%d", delegated, response.Code)
		}
	}
	var count int
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('agent.access.issue', 'agent.token.exchange')`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed issuance changed audit history: count=%d error=%v", count, err)
	}
	if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_token_issuance_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	for _, delegated := range []bool{false, true} {
		delegationAuditToken(t, f.request(ctx, delegated))
	}
}

func TestAgentTokenIssuanceHTTPRechecksOwnersAfterWaitingForLocks(t *testing.T) {
	f := newDelegationAuditFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	locked, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- f.store.InTx(ctx, func(q *db.Queries) error {
			if err := member.LockChainsTx(ctx, q, f.owner.ID); err != nil {
				return err
			}
			close(locked)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			return q.SetMemberStatus(ctx, db.SetMemberStatusParams{ID: f.owner.ID, SpaceID: f.owner.SpaceID, Status: "suspended"})
		})
	}()
	select {
	case <-locked:
	case err := <-writer:
		t.Fatalf("could not establish revocation barrier: %v", err)
	}
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- f.request(ctx, true) }()
	for {
		var waiting bool
		if err := f.store.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database()
			AND wait_event_type = 'Lock' AND query LIKE '%members%FOR UPDATE%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case out := <-response:
			t.Fatalf("token issuance bypassed its owner lock: status=%d", out.Code)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(release)
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	out := <-response
	if out.Code != http.StatusBadRequest || !strings.Contains(out.Body.String(), "invalid_scope") || strings.Contains(out.Body.String(), "access_token") {
		t.Fatalf("token issued using an inactive owner: status=%d", out.Code)
	}
	var count int
	if err := f.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'agent.token.exchange'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("denied issuance wrote a success event: count=%d error=%v", count, err)
	}
}
