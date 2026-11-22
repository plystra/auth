package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/application"
	"github.com/plystra/auth/internal/audit"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/store"
)

func TestBusinessAuditHTTPSnapshotsVerifiedAndAssertedSubjectChains(t *testing.T) {
	f := newBusinessAuditFixture(t)
	ctx := context.Background()
	parent, _, err := f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: f.owner.ID, Name: "business-parent"})
	if err != nil {
		t.Fatal(err)
	}
	child, childKey, err := f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: parent.ID, Name: "business-child", ExpiresAt: parent.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	body := f.body(CheckSubject{Token: childKey})
	body["request_digest"] = strings.Repeat("ab", 32)
	response := f.post(body, "")
	receipt := readBusinessReceipt(t, response)
	event := f.event(receipt.ID)
	if event.Action != "invoice.approve" || event.Outcome != "deny" || event.MemberID != child.ID || event.MemberType != "agent" ||
		event.ActorType != "application" || event.ApplicationID != "app_server_test" || event.ActorID == "" || event.Plane != "server" ||
		event.CredentialType != "application_api_key" || event.SpaceID != f.spaceID || event.PermissionKey != "auth.audit:write" ||
		len(event.OwnerChain) != 2 || event.OwnerChain[0].MemberID != parent.ID || event.OwnerChain[1].MemberID != f.owner.ID ||
		event.UserID != "" || event.DecisionID != "" || event.PolicyVersion != 0 || event.RequestID != "business-audit-test" {
		t.Fatalf("business event lost its provenance or subject chain: %+v", event)
	}
	if !strings.Contains(string(event.Metadata), `"event_source": "application_reported"`) || !strings.Contains(string(event.Metadata), `"subject_source": "token"`) ||
		!strings.Contains(string(event.Metadata), `"owner_chain_complete": true`) {
		t.Fatalf("business event provenance = %s", event.Metadata)
	}
	if err := f.agents.Delete(ctx, f.owner.ID, parent.ID); err != nil {
		t.Fatal(err)
	}
	historical := f.event(receipt.ID)
	if historical.OwnerChain[0].MemberID != parent.ID || historical.OwnerChain[1].MemberID != f.owner.ID {
		t.Fatal("Agent deletion rewrote the historical business audit chain")
	}
	if denied := f.post(body, ""); denied.Code != http.StatusUnauthorized || f.count() != 1 {
		t.Fatal("deleted Agent credentials produced another business event")
	}
	issued, err := f.sessions.CreateForMember(ctx, "usr_server_actor", f.owner.ID, nil, "business audit", 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := f.sessions.Signer.Sign(security.Claims{
		Issuer: f.sessions.Signer.Issuer(), Subject: "usr_server_actor", MemberID: f.owner.ID, SpaceID: f.spaceID,
		SessionID: issued.SessionID, Audience: "server-test-client", Type: "user", JWTID: "jti_business_user",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []CheckSubject{{Token: token}, {MemberID: f.owner.ID, UserID: "usr_server_actor"}} {
		stored := f.event(readBusinessReceipt(t, f.post(f.body(subject), "")).ID)
		if stored.MemberID != f.owner.ID || stored.UserID != "usr_server_actor" || len(stored.OwnerChain) != 0 {
			t.Fatalf("human business subject = %+v", stored)
		}
		if subject.Token == "" && !strings.Contains(string(stored.Metadata), `"subject_source": "application_assertion"`) {
			t.Fatal("ID assertion was recorded as a verified token identity")
		}
	}
	if denied := f.post(f.body(CheckSubject{Token: issued.AccessToken}), ""); denied.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-audience subject = %d %s", denied.Code, denied.Body.String())
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, issued.SessionID); err != nil {
		t.Fatal(err)
	}
	if denied := f.post(f.body(CheckSubject{Token: token}), ""); denied.Code != http.StatusUnauthorized || f.count() != 3 {
		t.Fatal("revoked user session produced another business event")
	}
	serialized, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{f.rawKey, childKey, token} {
		if strings.Contains(string(serialized), credential) {
			t.Fatal("persisted business event leaked credentials")
		}
	}
}

func TestBusinessAuditHTTPEnforcesCurrentApplicationAuthority(t *testing.T) {
	for _, scenario := range []struct {
		name, sql, code string
	}{
		{"key grant", `UPDATE api_keys SET scopes = '[]'::jsonb`, "PERMISSION_DENIED"},
		{"installation grant", `UPDATE authorization_grants SET revoked_at = now() WHERE grantee_member_id IN (SELECT member_id FROM application_installations)`, "NO_MATCHING_PERMISSION"},
		{"catalog disabled", `UPDATE permissions SET status = 'disabled' WHERE key = 'auth.audit:write'`, "PERMISSION_DISABLED"},
		{"principal kind", `UPDATE permissions SET principal_kinds = '["human","agent"]'::jsonb WHERE key = 'auth.audit:write'`, "PRINCIPAL_KIND_NOT_ALLOWED"},
		{"envelope", `INSERT INTO space_envelopes (space_id) SELECT space_id FROM application_installations`, "ENVELOPE_EXCLUDED"},
		{"installation suspended", `UPDATE application_installations SET status = 'suspended'`, "APPLICATION_NOT_INSTALLED"},
		{"member suspended", `UPDATE members SET status = 'suspended' WHERE type = 'application'`, "APPLICATION_NOT_INSTALLED"},
		{"key revoked", `UPDATE api_keys SET revoked_at = now()`, "unauthorized"},
		{"assertions disabled", `UPDATE api_keys SET allow_subject_assertion = false`, "VALIDATION_FAILED"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newBusinessAuditFixture(t)
			if _, err := f.store.Pool.Exec(context.Background(), scenario.sql); err != nil {
				t.Fatal(err)
			}
			denied := f.post(f.body(CheckSubject{MemberID: f.owner.ID}), "")
			if denied.Code < 400 || !strings.Contains(denied.Body.String(), `"code":"`+scenario.code+`"`) {
				t.Fatalf("business audit bypassed %s: %d %s", scenario.name, denied.Code, denied.Body.String())
			}
			if f.count() != 0 {
				t.Fatal("denied business event was appended")
			}
		})
	}
	f := newBusinessAuditFixture(t)
	ctx := context.Background()
	other, otherOwner, err := f.authz.CreateSpace(ctx, "usr_server_actor", "Other business tenant", "other-business-tenant")
	if err != nil {
		t.Fatal(err)
	}
	outside := f.body(CheckSubject{MemberID: f.owner.ID})
	outside["resource"] = CheckResource{Type: "invoice", ID: "inv_outside", SpaceID: other.ID}
	if denied := f.post(outside, ""); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "KEY_SCOPE_EXCLUDED") {
		t.Fatalf("out-of-scope target = %d %s", denied.Code, denied.Body.String())
	}
	outsider, outsiderKey, err := f.agents.Create(ctx, agent.CreateInput{OwnerMemberID: otherOwner.ID, Name: "outside-subject"})
	if err != nil {
		t.Fatal(err)
	}
	if denied := f.post(f.body(CheckSubject{Token: outsiderKey}), ""); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "KEY_SCOPE_EXCLUDED") || strings.Contains(denied.Body.String(), outsider.ID) {
		t.Fatalf("out-of-scope subject = %d %s", denied.Code, denied.Body.String())
	}
	group, err := f.authz.CreateGroup(ctx, f.owner.ID, f.spaceID, "Business audit scope", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE authorization_grants SET scope = 'group', anchor_space_id = NULL, anchor_group_id = $1
		WHERE grantee_member_id IN (SELECT member_id FROM application_installations)`, group.ID); err != nil {
		t.Fatal(err)
	}
	if denied := f.post(f.body(CheckSubject{MemberID: f.owner.ID}), ""); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "SCOPE_OUT_OF_BOUNDS") {
		t.Fatalf("group-scoped writer reached whole Space: %d %s", denied.Code, denied.Body.String())
	}
	allowed := f.body(CheckSubject{MemberID: f.owner.ID})
	allowed["resource"] = CheckResource{Type: "invoice", ID: "inv_group", SpaceID: f.spaceID, GroupID: group.ID}
	readBusinessReceipt(t, f.post(allowed, ""))
	missingGroup := f.body(CheckSubject{MemberID: f.owner.ID})
	missingGroup["resource"] = CheckResource{Type: "invoice", ID: "inv_group", SpaceID: f.spaceID, GroupID: "grp_missing_business"}
	if denied := f.post(missingGroup, ""); denied.Code != http.StatusForbidden || !strings.Contains(denied.Body.String(), "RESOURCE_GROUP_NOT_FOUND") {
		t.Fatalf("unresolved resource group = %d %s", denied.Code, denied.Body.String())
	}
}

func TestBusinessAuditHTTPIdempotencyAndStorageFailureAreAtomic(t *testing.T) {
	f := newBusinessAuditFixture(t)
	body := f.body(CheckSubject{MemberID: f.owner.ID})
	var requests sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 4)
	for range 4 {
		requests.Go(func() { responses <- f.post(body, "business-once") })
	}
	requests.Wait()
	close(responses)
	var receipt audit.BusinessReceipt
	for response := range responses {
		repeated := readBusinessReceipt(t, response)
		if receipt.ID == "" {
			receipt = repeated
		}
		if repeated.ID != receipt.ID || !repeated.OccurredAt.Equal(receipt.OccurredAt) {
			t.Fatal("idempotent business event returned another receipt")
		}
	}
	if repeated := readBusinessReceipt(t, f.post(body, "business-once")); repeated.ID != receipt.ID || !repeated.OccurredAt.Equal(receipt.OccurredAt) {
		t.Fatal("business event replay changed the receipt")
	}
	if f.count() != 1 {
		t.Fatal("business event retry appended duplicate audit records")
	}
	body["outcome"] = "success"
	if conflict := f.post(body, "business-once"); conflict.Code != http.StatusConflict {
		t.Fatalf("changed idempotent content = %d %s", conflict.Code, conflict.Body.String())
	}
	ctx := context.Background()
	if _, err := f.store.Pool.Exec(ctx, `CREATE FUNCTION reject_business_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.metadata->>'event_source' = 'application_reported' THEN RAISE EXCEPTION 'business audit unavailable'; END IF; RETURN NEW; END $$;
		CREATE TRIGGER reject_business_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_business_audit()`); err != nil {
		t.Fatal(err)
	}
	failed := f.post(body, "business-retry-after-failure")
	if failed.Code != http.StatusServiceUnavailable || !strings.Contains(failed.Body.String(), "UNAVAILABLE") || strings.Contains(failed.Body.String(), "business audit unavailable") || f.count() != 1 {
		t.Fatalf("audit write failure = %d %s", failed.Code, failed.Body.String())
	}
	if _, err := f.store.Pool.Exec(ctx, `DROP TRIGGER reject_business_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	if replayed := f.post(body, "business-retry-after-failure"); replayed.Code != http.StatusServiceUnavailable || f.count() != 1 {
		t.Fatal("failed idempotent request did not preserve its original result")
	}
	readBusinessReceipt(t, f.post(body, "business-recovered"))
	if f.count() != 2 {
		t.Fatal("recovery did not append exactly one new business event")
	}
	if _, err := f.store.Pool.Exec(ctx, `UPDATE api_keys SET revoked_at = now()`); err != nil {
		t.Fatal(err)
	}
	if denied := f.post(body, "business-recovered"); denied.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key replayed successful business event: %d", denied.Code)
	}
}

func TestBusinessAuditHTTPRejectsUntrustedFieldsAndCredentialContent(t *testing.T) {
	f := newBusinessAuditFixture(t)
	for _, mutate := range []func(map[string]any){
		func(body map[string]any) { body["metadata"] = map[string]string{"token": f.rawKey} },
		func(body map[string]any) { body["decision_id"] = "dec_forged" },
		func(body map[string]any) { body["owner_chain"] = []string{f.owner.ID} },
		func(body map[string]any) { body["request_digest"] = f.rawKey },
		func(body map[string]any) { body["action"] = "invalid event name" },
		func(body map[string]any) { body["outcome"] = "allow" },
		func(body map[string]any) {
			body["subject"] = map[string]string{"member_id": f.owner.ID, "role": "admin"}
		},
		func(body map[string]any) {
			body["subject"] = map[string]string{"member_id": f.owner.ID, "token": "ply_ag_invalid"}
		},
		func(body map[string]any) { body["resource"] = CheckResource{Type: "invoice", ID: f.rawKey} },
		func(body map[string]any) {
			body["resource"] = CheckResource{Type: "invoice", ID: "eyJhbGciOiJFUzI1NiJ9.payload.signature"}
		},
	} {
		body := f.body(CheckSubject{MemberID: f.owner.ID})
		mutate(body)
		if denied := f.post(body, ""); denied.Code != http.StatusBadRequest {
			t.Fatalf("untrusted business event = %d %s", denied.Code, denied.Body.String())
		}
	}
	if f.count() != 0 {
		t.Fatal("invalid business event was persisted")
	}
}

type businessAuditFixture struct {
	t        *testing.T
	store    *store.Store
	authz    *authorization.Service
	owner    authorization.Member
	spaceID  string
	rawKey   string
	sessions *session.Service
	agents   *agent.Service
	handler  http.Handler
}

func newBusinessAuditFixture(t *testing.T) *businessAuditFixture {
	t.Helper()
	// A write transaction must be sufficient for every subject lookup.
	st, authz, owner, spaceID, rawKey, sessions := newServerFixtureWithPoolLimit(t, 1)
	for _, statement := range []string{
		`UPDATE applications SET manifest_permissions = manifest_permissions || '["auth.audit:write"]'::jsonb`,
		`UPDATE application_installations SET approved_permissions = approved_permissions || '["auth.audit:write"]'::jsonb`,
		`UPDATE api_keys SET scopes = scopes || '["auth.audit:write"]'::jsonb`,
		`INSERT INTO role_permissions (role_id, permission_id) SELECT i.role_id, p.id FROM application_installations i CROSS JOIN permissions p WHERE p.key = 'auth.audit:write'`,
	} {
		if _, err := st.Pool.Exec(context.Background(), statement); err != nil {
			t.Fatal(err)
		}
	}
	agents := &agent.Service{Store: st}
	apps := &application.Service{Store: st, Authorization: authz, HMACKeys: [][]byte{[]byte(strings.Repeat("s", 32))}}
	api := &API{Applications: apps, Authorization: authz, Sessions: sessions, Agents: agents}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("business audit test", "1.0.0")))
	handler := route.MiddlewareWithIdempotency(route.Server, mux, st, func(ctx context.Context, _, authorization string) error {
		_, err := apps.AuthenticateKey(ctx, strings.TrimPrefix(authorization, "Bearer "))
		return err
	})
	return &businessAuditFixture{t: t, store: st, authz: authz, owner: owner, spaceID: spaceID, rawKey: rawKey, sessions: sessions, agents: agents, handler: handler}
}

func (f *businessAuditFixture) body(subject CheckSubject) map[string]any {
	return map[string]any{"subject": subject, "action": "invoice.approve", "outcome": "deny", "resource": CheckResource{Type: "invoice", ID: "inv_business"}}
}

func (f *businessAuditFixture) post(body map[string]any, idempotencyKey string) *httptest.ResponseRecorder {
	f.t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.t.Context(), 10*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/server/v1/audit/events", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+f.rawKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "business-audit-test")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, req)
	if strings.Contains(response.Body.String(), f.rawKey) || strings.Contains(response.Body.String(), "secret_hash") {
		f.t.Fatal("business audit response contains credential material")
	}
	return response
}

func (f *businessAuditFixture) count() int {
	f.t.Helper()
	var count int
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE metadata->>'event_source' = 'application_reported'`).Scan(&count); err != nil {
		f.t.Fatal(err)
	}
	return count
}

func (f *businessAuditFixture) event(id string) audit.Event {
	f.t.Helper()
	var raw []byte
	if err := f.store.Pool.QueryRow(context.Background(), `SELECT to_jsonb(a) FROM audit_logs a WHERE id = $1`, id).Scan(&raw); err != nil {
		f.t.Fatal(err)
	}
	var event audit.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		f.t.Fatal(err)
	}
	return event
}

func readBusinessReceipt(t *testing.T, response *httptest.ResponseRecorder) audit.BusinessReceipt {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("business audit = %d %s", response.Code, response.Body.String())
	}
	var out businessAuditOutput
	if err := json.Unmarshal(response.Body.Bytes(), &out.Body); err != nil || out.Body.Data.ID == "" || out.Body.Data.OccurredAt.IsZero() {
		t.Fatalf("invalid business audit receipt: %v", err)
	}
	return out.Body.Data
}
