package principal

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
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
	_, err = api.logout(context.Background(), &BearerInput{Authorization: "Bearer " + token})
	var public *apierr.Error
	if !strings.Contains(err.Error(), "user account") || !errors.As(err, &public) || public.Code != "USER_ACCOUNT_REQUIRED" {
		t.Fatalf("logout error = %v, want USER_ACCOUNT_REQUIRED", err)
	}
}
