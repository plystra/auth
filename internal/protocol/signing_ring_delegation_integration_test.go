package protocol

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/plystra/auth/internal/db"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
)

func TestOAuthDelegationUsesPersistedSigningRingAndRecoversAfterIntegrityFailure(t *testing.T) {
	ctx := t.Context()
	f := newOAuthDelegationFixture(t)
	seed := f.sessions.Signer
	var wrappingKey [32]byte
	if _, err := rand.Read(wrappingKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.InitializeSigningKeys(ctx, seed, wrappingKey[:]); err != nil {
		t.Fatal(err)
	}
	f.sessions.Signer = nil
	f.sessions.LoadSigner = func(ctx context.Context, q *db.Queries) (*security.Signer, error) {
		return store.LoadSigningKeys(ctx, q, seed.Issuer(), wrappingKey[:])
	}

	flipCiphertextBit := func() {
		t.Helper()
		result, err := f.store.Pool.Exec(ctx, `UPDATE signing_keys
			SET private_key_ciphertext = set_byte(private_key_ciphertext, 0, get_byte(private_key_ciphertext, 0) # 1)
			WHERE status = 'active'`)
		if err != nil || result.RowsAffected() != 1 {
			t.Fatal("could not change the test issuer's encrypted active key", err)
		}
	}
	requireError := func(candidate oauthDelegationFixture, wantStatus int, wantCode string) {
		t.Helper()
		resp := candidate.exchange(ctx, "app_redemption", "auth.members:read")
		var body struct {
			Error       struct{ Code string }
			AccessToken string `json:"access_token"`
		}
		if resp.Code != wantStatus || json.Unmarshal(resp.Body.Bytes(), &body) != nil || body.Error.Code != wantCode || body.AccessToken != "" {
			t.Fatalf("delegation failure returned status %d, want %d and error %q without a token", resp.Code, wantStatus, wantCode)
		}
		f.assertNoDelegation(t)
	}

	flipCiphertextBit()
	requireError(f, http.StatusServiceUnavailable, "temporarily_unavailable")
	flipCiphertextBit()
	invalid := f
	invalid.parentToken = "invalid"
	requireError(invalid, http.StatusBadRequest, "invalid_grant")

	token := delegationAuditToken(t, f.exchange(ctx, "app_redemption", "auth.members:read"))
	claims, err := seed.Verify(token, time.Now(), "app_redemption")
	if err != nil || claims.Type != "agent" || claims.Subject != f.child.ID || claims.Actor == nil || claims.Actor.Subject != f.agent.ID {
		t.Fatal("retry after repair did not issue the delegated identity")
	}
}
