package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/apierr"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var bootstrapDB *testdb.Harness

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var err error
	bootstrapDB, err = testdb.Start(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	if err := bootstrapDB.Close(context.Background()); err != nil && code == 0 {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func TestInitializePopulatesDefaultManifestAndScopedKey(t *testing.T) {
	ctx := context.Background()
	st := newBootstrapStore(t)

	result, err := Initialize(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if result.SpaceID != DefaultSpaceID || result.ApplicationID != DefaultApplicationID {
		t.Fatalf("bootstrap resources = %+v", result)
	}
	parts := strings.SplitN(result.APIKey, ".", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "ply_sk_") || parts[1] == "" {
		t.Fatalf("bootstrap key has invalid format: %q", result.APIKey)
	}

	var applicationScopes, keyScopes []byte
	var prefix string
	var secretHash []byte
	var expiresAt time.Time
	if err := st.Pool.QueryRow(ctx, `
		SELECT allowed_scopes
		FROM applications
		WHERE id = $1
	`, DefaultApplicationID).Scan(&applicationScopes); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `
		SELECT prefix, secret_hash, scopes, expires_at
		FROM api_keys
		WHERE application_id = $1
	`, DefaultApplicationID).Scan(&prefix, &secretHash, &keyScopes, &expiresAt); err != nil {
		t.Fatal(err)
	}
	if prefix != parts[0] {
		t.Fatalf("stored prefix = %q, want %q", prefix, parts[0])
	}
	wantHash := sha256.Sum256([]byte(parts[1]))
	if !bytes.Equal(secretHash, wantHash[:]) {
		t.Fatal("database does not store the API key digest")
	}
	if len(secretHash) != sha256.Size {
		t.Fatalf("secret hash length = %d, want %d", len(secretHash), sha256.Size)
	}
	wantScopes := []string{"auth.authz:check", "auth.tokens:introspect"}
	assertJSONScopes(t, applicationScopes, wantScopes)
	assertJSONScopes(t, keyScopes, wantScopes)
	remaining := time.Until(expiresAt)
	if remaining < 364*24*time.Hour || remaining > 366*24*time.Hour {
		t.Fatalf("bootstrap key lifetime = %s, want approximately one year", remaining)
	}
}

func TestInitializeRejectsSecondInvocationWithoutCreatingAnotherKey(t *testing.T) {
	ctx := context.Background()
	st := newBootstrapStore(t)
	if _, err := Initialize(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, st); err == nil {
		t.Fatal("second bootstrap initialization succeeded")
	} else {
		var apiError *apierr.Error
		if !errors.As(err, &apiError) || apiError.Code != "CONFLICT" {
			t.Fatalf("second initialization error = %v, want CONFLICT", err)
		}
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE application_id = $1`, DefaultApplicationID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("bootstrap API key count = %d, want 1", count)
	}
}

func TestInitializeRollsBackDefaultsWhenKeyCreationFails(t *testing.T) {
	ctx := context.Background()
	st := newBootstrapStore(t)
	if _, err := st.Pool.Exec(ctx, `DELETE FROM spaces WHERE id = $1`, DefaultSpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION fail_bootstrap_api_key() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'bootstrap key creation failure';
		END
		$$;
		CREATE TRIGGER fail_bootstrap_api_key
		BEFORE INSERT ON api_keys
		FOR EACH ROW EXECUTE FUNCTION fail_bootstrap_api_key();
	`); err != nil {
		t.Fatal(err)
	}

	if _, err := Initialize(ctx, st); err == nil {
		t.Fatal("bootstrap initialization succeeded despite key creation failure")
	}
	var spaces, applications, keys int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM spaces WHERE id = $1`, DefaultSpaceID).Scan(&spaces); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM applications WHERE id = $1`, DefaultApplicationID).Scan(&applications); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE application_id = $1`, DefaultApplicationID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if spaces != 0 || applications != 0 || keys != 0 {
		t.Fatalf("failed bootstrap left resources: spaces=%d applications=%d keys=%d", spaces, applications, keys)
	}
}

func newBootstrapStore(t *testing.T) *store.Store {
	t.Helper()
	database, err := bootstrapDB.Clone(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	st, err := store.Open(context.Background(), database.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

func assertJSONScopes(t *testing.T, raw []byte, want []string) {
	t.Helper()
	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("invalid scope JSON %q: %v", raw, err)
	}
	if len(got) != len(want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scopes = %v, want %v", got, want)
		}
	}
}
