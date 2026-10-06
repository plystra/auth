package session

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/security"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var sessionDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	sessionDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := sessionDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestRefreshTokenUsesPlystraPrefixEntropyHashingAndHMACKeyRotation(t *testing.T) {
	ctx := context.Background()
	database, err := sessionDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_refresh_test', 'refresh@example.test', 'refresh@example.test', 'test-password-hash', 'active')
	`); err != nil {
		t.Fatal(err)
	}
	signer, err := security.GenerateSigner("https://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	settings := func(context.Context) (Settings, error) {
		return Settings{AccessTTL: time.Minute, RefreshTTL: time.Hour, RefreshIdleTTL: 30 * time.Minute}, nil
	}
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	legacy := &Service{Store: st, Signer: signer, HMACKeys: [][]byte{oldKey}, Settings: settings}
	rotating := &Service{Store: st, Signer: signer, HMACKeys: [][]byte{newKey, oldKey}, Settings: settings}
	issued, err := legacy.Create(ctx, "usr_refresh_test", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(issued.RefreshToken, "ply_rt_") {
		t.Fatalf("refresh token prefix = %q, want ply_rt_", issued.RefreshToken)
	}
	rawEntropy, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(issued.RefreshToken, "ply_rt_"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rawEntropy) != 32 {
		t.Fatalf("refresh token entropy = %d bytes, want 32", len(rawEntropy))
	}
	var stored []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM refresh_tokens WHERE session_id = $1`, issued.SessionID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored, []byte(issued.RefreshToken)) || !bytes.Equal(stored, hmacSHA256(oldKey, issued.RefreshToken)) {
		t.Fatal("refresh token was not stored as an HMAC hash")
	}
	rotated, err := rotating.Refresh(ctx, issued.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rotated.RefreshToken, "ply_rt_") {
		t.Fatalf("rotated refresh token prefix = %q, want ply_rt_", rotated.RefreshToken)
	}
	var rotatedHash []byte
	if err := st.Pool.QueryRow(ctx, `SELECT token_hash FROM refresh_tokens WHERE session_id = $1 AND used_at IS NULL`, issued.SessionID).Scan(&rotatedHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rotatedHash, hmacSHA256(newKey, rotated.RefreshToken)) {
		t.Fatal("rotated refresh token was not hashed with the current HMAC key")
	}
	var successfulRefreshAudits int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'auth.session.refresh' AND actor_id = 'usr_refresh_test'`).Scan(&successfulRefreshAudits); err != nil {
		t.Fatal(err)
	}
	if successfulRefreshAudits != 1 {
		t.Fatalf("successful refresh audit count = %d, want 1", successfulRefreshAudits)
	}
	if _, err := rotating.Refresh(ctx, issued.RefreshToken); err == nil {
		t.Fatal("replayed refresh token was accepted")
	} else {
		var public *apierr.Error
		if !errors.As(err, &public) || public.Code != "invalid_grant" {
			t.Fatalf("replayed refresh error = %v, want invalid_grant", err)
		}
	}
	var active int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL`, issued.SessionID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("replayed refresh left %d active family tokens", active)
	}
	var replayAudits int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE action = 'auth.session.refresh_replay' AND metadata->>'priority' = 'high'
	`).Scan(&replayAudits); err != nil {
		t.Fatal(err)
	}
	if replayAudits != 1 {
		t.Fatalf("replay audit count = %d, want 1", replayAudits)
	}
	var leakedAuditTokens int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_logs
		WHERE metadata::text LIKE '%' || $1 || '%' OR metadata::text LIKE '%' || $2 || '%'
	`, issued.RefreshToken, rotated.RefreshToken).Scan(&leakedAuditTokens); err != nil {
		t.Fatal(err)
	}
	if leakedAuditTokens != 0 {
		t.Fatal("refresh token appeared in audit metadata")
	}
	if _, stillActive, err := rotating.Introspect(ctx, rotated.AccessToken, security.DefaultApplicationAudience); err != nil {
		t.Fatal(err)
	} else if stillActive {
		t.Fatal("replayed refresh token did not revoke the session")
	}

	concurrent, err := legacy.Create(ctx, "usr_refresh_test", nil, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, refreshErr := rotating.Refresh(ctx, concurrent.RefreshToken)
			results <- refreshErr
		}()
	}
	close(start)
	successes := 0
	failures := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		} else {
			failures++
			var public *apierr.Error
			if !errors.As(err, &public) || public.Code != "invalid_grant" {
				t.Fatalf("concurrent refresh error = %v, want invalid_grant", err)
			}
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent refresh results: successes=%d failures=%d, want one each", successes, failures)
	}
	var concurrentActive int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL`, concurrent.SessionID).Scan(&concurrentActive); err != nil {
		t.Fatal(err)
	}
	if concurrentActive != 0 {
		t.Fatalf("concurrent refresh replay left %d active tokens", concurrentActive)
	}
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
