package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var applicationDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	applicationDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := applicationDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestAPIKeyHMACStorageExpiryAndRotation(t *testing.T) {
	ctx := context.Background()
	st := newKeyStore(t)
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	issuer := &Service{Store: st, HMACKeys: [][]byte{oldKey}}
	for _, expiry := range []*time.Time{nil, timePointer(time.Now().Add(-time.Minute)), timePointer(time.Now().Add(366 * 24 * time.Hour))} {
		if _, err := issuer.CreateKey(ctx, "app_key_test", "invalid", nil, expiry); err == nil {
			t.Fatalf("accepted invalid API key expiry %v", expiry)
		}
	}
	expires := time.Now().Add(time.Hour)
	raw, err := issuer.CreateKey(ctx, "app_key_test", "hmac", []string{"auth.authz:check"}, &expires)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(raw, ".", 2)
	var stored []byte
	var scheme string
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash, hash_scheme FROM api_keys WHERE prefix = $1`, parts[0]).Scan(&stored, &scheme); err != nil {
		t.Fatal(err)
	}
	legacyDigest := sha256.Sum256([]byte(parts[1]))
	if scheme != "hmac_sha256" || !bytes.Equal(stored, apiKeyHash(oldKey, parts[1])) || bytes.Equal(stored, legacyDigest[:]) {
		t.Fatal("API key was not stored as a keyed digest")
	}
	if _, err := issuer.AuthenticateKey(ctx, raw+"wrong"); err == nil {
		t.Fatal("incorrect API key secret authenticated")
	}
	rotating := &Service{Store: st, HMACKeys: [][]byte{newKey, oldKey}}
	if _, err := rotating.AuthenticateKey(ctx, raw); err != nil {
		t.Fatalf("old HMAC key was not accepted during rotation: %v", err)
	}
	if _, err := (&Service{Store: st, HMACKeys: [][]byte{newKey}}).AuthenticateKey(ctx, raw); err == nil {
		t.Fatal("old API key authenticated after its HMAC key was removed")
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE prefix = $1`, parts[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := rotating.AuthenticateKey(ctx, raw); err == nil {
		t.Fatal("expired API key authenticated")
	}
}

func TestLegacyAPIKeyHashesUpgradeBeforeAuthentication(t *testing.T) {
	ctx := context.Background()
	st := newKeyStore(t)
	key := []byte(strings.Repeat("k", 32))
	svc := &Service{Store: st, HMACKeys: [][]byte{key}}
	expires := time.Now().Add(time.Hour)
	raw, err := svc.CreateKey(ctx, "app_key_test", "legacy", nil, &expires)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(raw, ".", 2)
	legacyDigest := sha256.Sum256([]byte(parts[1]))
	if _, err := st.Pool.Exec(ctx, `UPDATE api_keys SET secret_hash = $1, hash_scheme = 'sha256_legacy' WHERE prefix = $2`, legacyDigest[:], parts[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateKey(ctx, raw); err == nil {
		t.Fatal("legacy SHA-256 key authenticated before upgrade")
	}
	if err := svc.UpgradeLegacyKeyHashes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpgradeLegacyKeyHashes(ctx); err != nil {
		t.Fatalf("repeated upgrade failed: %v", err)
	}
	var stored []byte
	var scheme string
	if err := st.Pool.QueryRow(ctx, `SELECT secret_hash, hash_scheme FROM api_keys WHERE prefix = $1`, parts[0]).Scan(&stored, &scheme); err != nil {
		t.Fatal(err)
	}
	if scheme != "hmac_sha256" || bytes.Equal(stored, legacyDigest[:]) || !bytes.Equal(stored, apiKeyHash(key, parts[1])) {
		t.Fatal("legacy digest was not converted to HMAC")
	}
	if _, err := svc.AuthenticateKey(ctx, raw); err != nil {
		t.Fatalf("upgraded API key failed to authenticate: %v", err)
	}
}

func newKeyStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	database, err := applicationDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(ctx, database.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool.Exec(ctx, `INSERT INTO spaces (id, name, slug) VALUES ('spc_key_test', 'Key Test', 'key-test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO applications (id, space_id, name, client_id) VALUES ('app_key_test', 'spc_key_test', 'Key Test', 'key-test')`); err != nil {
		t.Fatal(err)
	}
	return st
}

func timePointer(value time.Time) *time.Time { return &value }
