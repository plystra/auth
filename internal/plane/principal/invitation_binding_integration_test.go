package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/agent"
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/invitation"
	"github.com/plystra/auth/internal/mail"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/session"
	"github.com/plystra/auth/internal/space"
	"github.com/plystra/auth/internal/store"
)

func bindingInvitationHandler(t *testing.T, st *store.Store, authz *authorization.Service, sessions *session.Service, signer *security.Signer) http.Handler {
	t.Helper()
	authz.StepUp = sessions
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Invitations: &invitation.Service{Store: st, Authorization: authz}}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("binding invitation test", "1.0.0")))
	return route.Middleware(route.Principal, mux)
}

func postBindingInvitation(t *testing.T, handler http.Handler, spaceID, memberID, email, accessToken string) (int, invitationResponse) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": email, "member_id": memberID})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/spaces/"+spaceID+"/invitations", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var result struct {
		Data invitationResponse `json:"data"`
	}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, result.Data
}

func acceptBindingInvitation(t *testing.T, handler http.Handler, token, accessToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/invitations/accept", strings.NewReader(fmt.Sprintf(`{"token":%q}`, token)))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func createVerifiedInvitee(t *testing.T, st *store.Store, sessions *session.Service, userID, email string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at)
		VALUES ($1, $2, $2, 'hash', 'active', now())
	`, userID, email); err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.Create(ctx, userID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	return tokens.AccessToken
}

func issueExistingMemberInvitation(t *testing.T, st *store.Store, handler http.Handler, sessionID, accessToken, spaceID, memberID, email string) invitationResponse {
	t.Helper()
	seedStepUpProof(t, st, sessionID, "invitations.create", map[string]any{
		"space_id": spaceID, "email": email, "member_id": memberID, "expires_at": time.Time{},
	})
	status, created := postBindingInvitation(t, handler, spaceID, memberID, email, accessToken)
	if status != http.StatusOK || created.Token == "" {
		t.Fatalf("binding invitation creation status = %d", status)
	}
	return created
}

func TestExistingMemberInvitationRechecksDeltaAtAcceptance(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Shared position", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, target.ID, "auth.members:read")
	invitedToken := createVerifiedInvitee(t, st, sessions, "usr_binding_invitee", "binding@example.test")
	ownerTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	handler := bindingInvitationHandler(t, st, authz, sessions, signer)
	proofRequest := map[string]any{"space_id": spaceID, "email": "binding@example.test", "member_id": target.ID, "expires_at": time.Time{}}
	if status, _ := postBindingInvitation(t, handler, spaceID, target.ID, "binding@example.test", ownerTokens.AccessToken); status == http.StatusOK {
		t.Fatal("existing-member invitation did not require step-up")
	}
	seedStepUpProof(t, st, ownerTokens.SessionID, "invitations.create", proofRequest)
	status, created := postBindingInvitation(t, handler, spaceID, target.ID, "binding@example.test", ownerTokens.AccessToken)
	if status != http.StatusOK || created.Token == "" {
		t.Fatalf("binding invitation creation status = %d", status)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = now() WHERE holder_member_id = $1 AND source = 'system'`, owner.ID); err != nil {
		t.Fatal(err)
	}
	rejected := acceptBindingInvitation(t, handler, created.Token, invitedToken)
	if rejected.Code == http.StatusOK || !strings.Contains(rejected.Body.String(), "AUTHORITY_DELTA_NOT_COVERED") {
		t.Fatalf("acceptance ignored revoked delegation: status=%d", rejected.Code)
	}
	var bound, consumed int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_binding_invitee' AND member_id = $1`, target.ID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if bound != 0 || consumed != 0 {
		t.Fatalf("rejected acceptance left binding=%d consumed=%d", bound, consumed)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE assign_rights SET revoked_at = NULL WHERE holder_member_id = $1 AND source = 'system'`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET status = 'revoked', revoked_at = now() WHERE user_id = 'usr_principal_actor' AND member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if response := acceptBindingInvitation(t, handler, created.Token, invitedToken); response.Code == http.StatusOK || !strings.Contains(response.Body.String(), "BINDING_REVOKED") {
		t.Fatalf("acceptance ignored revoked inviter binding: status=%d", response.Code)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE user_members SET status = 'active', revoked_at = NULL WHERE user_id = 'usr_principal_actor' AND member_id = $1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	accepted := acceptBindingInvitation(t, handler, created.Token, invitedToken)
	if accepted.Code != http.StatusOK || !strings.Contains(accepted.Body.String(), target.ID) {
		t.Fatalf("valid binding invitation acceptance status = %d", accepted.Code)
	}
	if again := acceptBindingInvitation(t, handler, created.Token, invitedToken); again.Code == http.StatusOK {
		t.Fatal("binding invitation token was reusable")
	}
}

func TestExistingMemberInvitationCreationRejectsUncoveredDelta(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Privileged position", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, target.ID, "auth.members:read")
	actor, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Limited inviter", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_limited_inviter', 'limited@example.test', 'limited@example.test', 'hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO user_members (user_id, member_id) VALUES ('usr_limited_inviter', $1)`, actor.ID); err != nil {
		t.Fatal(err)
	}
	seedTestInlineGrant(t, st, spaceID, owner.ID, actor.ID, "auth.bindings:manage")
	seedTestInlineGrant(t, st, spaceID, owner.ID, actor.ID, "auth.grants:assign")
	tokens, err := sessions.CreateForMember(ctx, "usr_limited_inviter", actor.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	handler := bindingInvitationHandler(t, st, authz, sessions, signer)
	seedStepUpProof(t, st, tokens.SessionID, "invitations.create", map[string]any{"space_id": spaceID, "email": "recipient@example.test", "member_id": target.ID, "expires_at": time.Time{}})
	status, _ := postBindingInvitation(t, handler, spaceID, target.ID, "recipient@example.test", tokens.AccessToken)
	if status == http.StatusOK {
		t.Fatal("limited inviter created a binding invitation without assignment coverage")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE email_normalized = 'recipient@example.test'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("uncovered binding invitation was stored")
	}
}

func TestExistingMemberInvitationEnforcesSingleBindingPolicy(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "usr_principal_actor", spaceID, "Personal position", "human", "single")
	if err != nil {
		t.Fatal(err)
	}
	ownerTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	handler := bindingInvitationHandler(t, st, authz, sessions, signer)
	seedStepUpProof(t, st, ownerTokens.SessionID, "invitations.create", map[string]any{
		"space_id": spaceID, "email": "another@example.test", "member_id": target.ID, "expires_at": time.Time{},
	})
	status, _ := postBindingInvitation(t, handler, spaceID, target.ID, "another@example.test", ownerTokens.AccessToken)
	if status == http.StatusOK {
		t.Fatal("a second user was invited into a single-binding member")
	}
}

func TestExistingMemberInvitationRejectsAgentIssuer(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Human position", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	agents := &agent.Service{Store: st}
	created, _, err := agents.Create(ctx, agent.CreateInput{
		OwnerMemberID: owner.ID, CreatedByUser: "usr_principal_actor", Name: "invitation-agent",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := sessions.CreateAgentAccess(ctx, created.ID, spaceID, security.DefaultApplicationAudience)
	if err != nil {
		t.Fatal(err)
	}
	handler := bindingInvitationHandler(t, st, authz, sessions, signer)
	status, _ := postBindingInvitation(t, handler, spaceID, target.ID, "agent-invite@example.test", tokens.AccessToken)
	if status == http.StatusOK {
		t.Fatal("an Agent issued an existing-member binding invitation")
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE email_normalized = 'agent-invite@example.test'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("an Agent-issued binding invitation was stored")
	}
}

func TestExistingMemberInvitationAuditFailureAndConcurrentSingleUse(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Shared audit position", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	invitedToken := createVerifiedInvitee(t, st, sessions, "usr_binding_audit", "binding-audit@example.test")
	ownerTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	handler := bindingInvitationHandler(t, st, authz, sessions, signer)
	created := issueExistingMemberInvitation(t, st, handler, ownerTokens.SessionID, ownerTokens.AccessToken, spaceID, target.ID, "binding-audit@example.test")
	if _, err := st.Pool.Exec(ctx, `
		CREATE FUNCTION reject_binding_invitation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.action = 'invitation.accept' THEN RAISE EXCEPTION 'audit rejected'; END IF; RETURN NEW; END;
		$$;
		CREATE TRIGGER reject_binding_invitation_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_binding_invitation_audit()
	`); err != nil {
		t.Fatal(err)
	}
	if response := acceptBindingInvitation(t, handler, created.Token, invitedToken); response.Code == http.StatusOK {
		t.Fatal("binding invitation succeeded despite audit failure")
	}
	var bindings, consumed int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = 'usr_binding_audit' AND member_id = $1`, target.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 || consumed != 0 {
		t.Fatalf("audit failure left bindings=%d consumed=%d", bindings, consumed)
	}
	if _, err := st.Pool.Exec(ctx, `DROP TRIGGER reject_binding_invitation_audit ON audit_logs; DROP FUNCTION reject_binding_invitation_audit()`); err != nil {
		t.Fatal(err)
	}
	const attempts = 4
	var wg sync.WaitGroup
	results := make(chan int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- acceptBindingInvitation(t, handler, created.Token, invitedToken).Code
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for status := range results {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent acceptance successes = %d, want 1", successes)
	}
}

func TestNewAccountInvitationBindsExistingMemberAfterEmailVerification(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	target, err := authz.CreateMember(ctx, owner.ID, "", spaceID, "Shared signup position", "human", "shared")
	if err != nil {
		t.Fatal(err)
	}
	ownerTokens, err := sessions.CreateForMember(ctx, "usr_principal_actor", owner.ID, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	handler := bindingInvitationHandler(t, st, authz, sessions, signer)
	created := issueExistingMemberInvitation(t, st, handler, ownerTokens.SessionID, ownerTokens.AccessToken, spaceID, target.ID, "new-binding@example.test")
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'invite_only'`); err != nil {
		t.Fatal(err)
	}
	sender := &invitationMailSender{body: make(chan string, 1)}
	mailer, err := mail.New(secret.New(strings.Repeat("d", 32)), st.Jobs, sender)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &account.Service{
		Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st},
		Mailer: mailer, Sessions: sessions, Authorization: authz,
	}
	invites := &invitation.Service{Store: st, Accounts: accounts, Authorization: authz}
	accounts.Invitations = invites
	registered, err := invites.RegisterNewUser(ctx, created.Token, "new-binding@example.test", "a sufficiently long password")
	if err != nil || !registered.PendingVerification {
		t.Fatalf("invited registration = %+v, %v", registered, err)
	}
	var userID, status string
	if err := st.Pool.QueryRow(ctx, `SELECT id, status FROM users WHERE email_normalized = 'new-binding@example.test'`).Scan(&userID, &status); err != nil || status != "pending" {
		t.Fatalf("account before verification = status %q, error %v", status, err)
	}
	var bindings, consumed int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = $1 AND member_id = $2`, userID, target.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if bindings != 0 || consumed != 0 {
		t.Fatal("registration bound a member or consumed an invitation before email verification")
	}
	var jobArgs []byte
	if err := st.Pool.QueryRow(ctx, `SELECT args FROM river_job WHERE kind = 'email_delivery'`).Scan(&jobArgs); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	if err := json.Unmarshal(jobArgs, &payload); err != nil {
		t.Fatal(err)
	}
	if err := mailer.DeliverEmail(ctx, payload.Ciphertext); err != nil {
		t.Fatal(err)
	}
	verification := strings.TrimSpace(strings.TrimPrefix(<-sender.body, "Enter this verification token in Plystra Auth: "))
	if err := accounts.VerifyEmail(ctx, verification); err != nil {
		t.Fatalf("invited account verification = %v", err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM user_members WHERE user_id = $1 AND member_id = $2 AND status = 'active'`, userID, target.ID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if bindings != 1 || consumed != 1 {
		t.Fatalf("verified invitation left bindings=%d consumed=%d", bindings, consumed)
	}
}
