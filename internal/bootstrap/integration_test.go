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
	"github.com/plystra/auth/internal/authorization"
	"github.com/plystra/auth/internal/authz/engine"
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

	var applicationScopes, manifest, keyScopes, restrictions []byte
	var prefix string
	var secretHash []byte
	var expiresAt time.Time
	if err := st.Pool.QueryRow(ctx, `
		SELECT allowed_scopes, manifest_permissions
		FROM applications
		WHERE id = $1
	`, DefaultApplicationID).Scan(&applicationScopes, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := st.Pool.QueryRow(ctx, `
		SELECT prefix, secret_hash, scopes, restrict_to, expires_at
		FROM api_keys
		WHERE application_id = $1
	`, DefaultApplicationID).Scan(&prefix, &secretHash, &keyScopes, &restrictions, &expiresAt); err != nil {
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
	assertJSONScopes(t, manifest, wantScopes)
	assertJSONScopes(t, keyScopes, wantScopes)
	var restricted []struct {
		SpaceID string `json:"space_id"`
	}
	if err := json.Unmarshal(restrictions, &restricted); err != nil || len(restricted) != 1 || restricted[0].SpaceID != DefaultSpaceID {
		t.Fatalf("bootstrap key restrictions = %s, error = %v", restrictions, err)
	}
	var memberID, scope, status string
	if err := st.Pool.QueryRow(ctx, `
		SELECT member_id, scope, status FROM application_installations
		WHERE application_id = $1 AND space_id = $2
	`, DefaultApplicationID, DefaultSpaceID).Scan(&memberID, &scope, &status); err != nil {
		t.Fatal(err)
	}
	if scope != "space" || status != "active" {
		t.Fatalf("bootstrap installation scope=%q status=%q", scope, status)
	}
	decision, _, err := (&authorization.Service{Store: st}).Check(ctx, authorization.CheckRequest{
		MemberID: memberID, Permission: "auth.authz:check", ResourceSpace: DefaultSpaceID,
	})
	if err != nil || decision.Effect != engine.Allow {
		t.Fatalf("bootstrap application member decision = %+v, %v", decision, err)
	}
	remaining := time.Until(expiresAt)
	if remaining < 364*24*time.Hour || remaining > 366*24*time.Hour {
		t.Fatalf("bootstrap key lifetime = %s, want approximately one year", remaining)
	}
}

func TestInitializeRecreatesDefaultInstallationAfterCleanup(t *testing.T) {
	ctx := context.Background()
	st := newBootstrapStore(t)
	if _, err := st.Pool.Exec(ctx, `DELETE FROM spaces WHERE id = $1`, DefaultSpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, st); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.Pool.QueryRow(ctx, `
		SELECT count(*) FROM application_installations
		WHERE application_id = $1 AND space_id = $2 AND status = 'active'
	`, DefaultApplicationID, DefaultSpaceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("recreated default installation count=%d error=%v", count, err)
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
