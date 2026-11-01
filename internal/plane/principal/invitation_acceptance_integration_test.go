package principal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/invitation"
	"github.com/plystra/auth/internal/route"
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
		request := httptest.NewRequest(http.MethodPost, "/v1/invitations/"+raw+"/accept", strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
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
