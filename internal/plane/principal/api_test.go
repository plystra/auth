package principal

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/route"
	"github.com/plystra/auth/internal/security"
)

func TestLogoutRejectsAgentAccessTokenWithUserAccountRequired(t *testing.T) {
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := signer.Sign(security.Claims{
		Issuer: signer.Issuer(), Subject: "mem_agent", MemberID: "mem_agent",
		Audience: security.DefaultApplicationAudience, ExpiresAt: now.Add(time.Minute).Unix(),
		IssuedAt: now.Unix(), JWTID: "jti_test", Type: "agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	api := &API{Signer: signer}
	_, err = api.logout(context.Background(), &LogoutInput{Authorization: "Bearer " + token})
	var public *apierr.Error
	if !strings.Contains(err.Error(), "user account") || !errors.As(err, &public) || public.Code != "USER_ACCOUNT_REQUIRED" {
		t.Fatalf("logout error = %v, want USER_ACCOUNT_REQUIRED", err)
	}
}

func TestSignOutRouteDeclaresUserAccountSubject(t *testing.T) {
	api := &API{}
	api.Register(humago.New(http.NewServeMux(), route.HumaConfig("principal test", "1.0.0")))
	for _, spec := range route.Specs() {
		if spec.Name != "auth.sign_out" {
			continue
		}
		if len(spec.Subjects) != 1 || spec.Subjects[0] != route.User || spec.Permission != "" {
			t.Fatalf("sign-out route = %+v, want U subject without member permission", spec)
		}
		return
	}
	t.Fatal("sign-out route was not registered")
}
