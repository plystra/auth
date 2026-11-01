package principal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/account"
	"github.com/plystra/auth/internal/invitation"
	"github.com/plystra/auth/internal/mail"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/secret"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/space"
)

func TestVerifiedUserAcceptsInvitationThroughPrincipalHTTP(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	const invitedUser = "usr_invited_http"
	const otherUser = "usr_other_http"
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified_at)
		VALUES ($1, 'invitee@example.test', 'invitee@example.test', 'hash', 'active', now()),
		       ($2, 'other@example.test', 'other@example.test', 'hash', 'active', now())
	`, invitedUser, otherUser); err != nil {
		t.Fatal(err)
	}
	inviteService := &invitation.Service{Store: st}
	created, raw, err := inviteService.CreateForActor(ctx, "member", owner.ID, invitation.CreateInput{SpaceID: spaceID, Email: "Invitee@Example.Test"})
	if err != nil {
		t.Fatal(err)
	}
	otherTokens, err := sessions.Create(ctx, otherUser, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	invitedTokens, err := sessions.Create(ctx, invitedUser, nil, "test", 1)
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Authorization: authz, Sessions: sessions, Signer: signer, Invitations: inviteService}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal invitation test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	accept := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v1/invitations/accept", strings.NewReader(`{"token":"`+raw+`"}`))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	legacy := httptest.NewRequest(http.MethodPost, "/v1/invitations/"+raw+"/accept", strings.NewReader(`{}`))
	legacy.Header.Set("Authorization", "Bearer "+invitedTokens.AccessToken)
	legacy.Header.Set("Content-Type", "application/json")
	legacyResponse := httptest.NewRecorder()
	handler.ServeHTTP(legacyResponse, legacy)
	if legacyResponse.Code != http.StatusNotFound {
		t.Fatalf("invitation token remains accepted in URL: status=%d", legacyResponse.Code)
	}
	wrong := accept(otherTokens.AccessToken)
	if wrong.Code != http.StatusBadRequest || !strings.Contains(wrong.Body.String(), "invalid_grant") {
		t.Fatalf("different verified email accepted invitation: status=%d body=%s", wrong.Code, wrong.Body.String())
	}
	response := accept(invitedTokens.AccessToken)
	if response.Code != http.StatusOK {
		t.Fatalf("verified user invitation acceptance: status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		Data invitation.Acceptance `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.SpaceID != spaceID || !strings.HasPrefix(body.Data.MemberID, "mem_") || strings.Contains(response.Body.String(), raw) {
		t.Fatalf("unexpected invitation acceptance response: %s", response.Body.String())
	}
	var bindings, consumed, audits int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM user_members
		WHERE user_id = $1 AND member_id = $2 AND status = 'active'
	`, invitedUser, body.Data.MemberID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'invitation.accept' AND actor_id = $1`, invitedUser).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if bindings != 1 || consumed != 1 || audits != 1 {
		t.Fatalf("acceptance state: bindings=%d consumed=%d audits=%d", bindings, consumed, audits)
	}
	if repeated := accept(invitedTokens.AccessToken); repeated.Code != http.StatusBadRequest {
		t.Fatalf("invitation was reusable: status=%d", repeated.Code)
	}
}

type invitationMailSender struct{ body chan string }

func (s *invitationMailSender) Send(_ context.Context, _, _, body string) error {
	s.body <- body
	return nil
}

func TestNewUserInvitationRegistrationAndVerificationThroughPrincipalHTTP(t *testing.T) {
	ctx := context.Background()
	st, authz, owner, spaceID, sessions, signer := newPrincipalFixture(t)
	if _, err := st.Pool.Exec(ctx, `UPDATE instance_settings SET registration_mode = 'invite_only'`); err != nil {
		t.Fatal(err)
	}
	sender := &invitationMailSender{body: make(chan string, 1)}
	mailer, err := mail.New(secret.New(strings.Repeat("d", 32)), st.Jobs, sender)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &account.Service{Store: st, Passwords: security.DefaultPasswordHasher(), Settings: &space.Service{Store: st}, Mailer: mailer, Sessions: sessions, Authorization: authz}
	invites := &invitation.Service{Store: st, Accounts: accounts}
	accounts.Invitations = invites
	created, raw, err := invites.CreateForActor(ctx, "member", owner.ID, invitation.CreateInput{SpaceID: spaceID, Email: "new@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Accounts: accounts, Authorization: authz, Sessions: sessions, Signer: signer, Invitations: invites}
	mux := http.NewServeMux()
	api.Register(humago.New(mux, route.HumaConfig("principal invitation registration test", "1.0.0")))
	handler := route.Middleware(route.Principal, mux)
	request := httptest.NewRequest(http.MethodPost, "/v1/invitations/accept", strings.NewReader(fmt.Sprintf(`{"token":%q,"email":"NEW@example.test","password":"a sufficiently long password"}`, raw)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"pending_verification":true`) || strings.Contains(response.Body.String(), raw) || strings.Contains(response.Body.String(), spaceID) {
		t.Fatalf("invited registration: status=%d body=%s", response.Code, response.Body.String())
	}
	var userID, status string
	if err := st.Pool.QueryRow(ctx, `SELECT id, status FROM users WHERE email_normalized = 'new@example.test'`).Scan(&userID, &status); err != nil || status != "pending" {
		t.Fatalf("pending invited account: user=%q status=%q error=%v", userID, status, err)
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
	var verification string
	select {
	case body := <-sender.body:
		verification = strings.TrimSpace(strings.TrimPrefix(body, "Enter this verification token in Plystra Auth: "))
	case <-time.After(time.Second):
		t.Fatal("verification mail was not delivered")
	}
	if !strings.HasPrefix(verification, "ev_") {
		t.Fatal("verification mail did not contain a valid token")
	}
	verifyRequest := httptest.NewRequest(http.MethodPost, "/v1/auth/email/verify", strings.NewReader(fmt.Sprintf(`{"token":%q}`, verification)))
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK {
		t.Fatalf("verify invited email: status=%d body=%s", verifyResponse.Code, verifyResponse.Body.String())
	}
	var memberID string
	if err := st.Pool.QueryRow(ctx, `SELECT m.id FROM members m JOIN user_members um ON um.member_id = m.id WHERE um.user_id = $1 AND m.space_id = $2 AND um.status = 'active'`, userID, spaceID).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(memberID, "mem_") {
		t.Fatalf("invited member ID = %q", memberID)
	}
	var consumed, pending, audits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM invitation_tokens WHERE id = $1 AND consumed_at IS NOT NULL`, created.ID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM pending_invitation_registrations WHERE user_id = $1`, userID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'invitation.accept' AND actor_id = $1`, userID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if consumed != 1 || pending != 0 || audits != 1 {
		t.Fatalf("invited acceptance state: consumed=%d pending=%d audits=%d", consumed, pending, audits)
	}
	loggedIn, err := accounts.Login(ctx, account.LoginInput{Email: "new@example.test", Password: "a sufficiently long password"})
	if err != nil || loggedIn.Tokens == nil {
		t.Fatalf("invited user login = %+v, %v", loggedIn, err)
	}
	claims, err := signer.Verify(loggedIn.Tokens.AccessToken, time.Now().UTC(), security.DefaultApplicationAudience)
	if err != nil || claims.MemberID != memberID || claims.SpaceID != spaceID {
		t.Fatalf("invited user signed into wrong member: claims=%+v error=%v", claims, err)
	}
}
