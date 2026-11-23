package session

import (
	"context"
	"database/sql"
	"testing"

	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/migrations"
	"github.com/pressly/goose/v3"
)

func TestSSOSessionOriginMigrationRequiresReauthenticationOnlyForLegacySSO(t *testing.T) {
	ctx := t.Context()
	database, err := sessionDB.CloneEmpty(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	admin, err := sql.Open("pgx", database.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	if _, err := admin.ExecContext(ctx, `GRANT USAGE, CREATE ON SCHEMA public TO plystra_auth_owner`); err != nil {
		t.Fatal(err)
	}
	owner, err := sql.Open("pgx", database.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, owner, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 67); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `
		INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_sso_legacy', 'legacy@example.test', 'legacy@example.test', 'unused', 'active');
		INSERT INTO members (id, space_id, name, type, binding_policy, status)
		SELECT 'mem_current', id, 'Current member', 'human', 'single', 'active' FROM spaces WHERE slug = 'default';
		INSERT INTO user_members (user_id, member_id) VALUES ('usr_sso_legacy', 'mem_current');
		INSERT INTO sessions (id, user_id, member_id, token_hash, expires_at, auth_methods)
		SELECT 'ses_legacy_' || method, 'usr_sso_legacy', 'mem_current', convert_to(method, 'UTF8'),
			now() + interval '1 hour', ARRAY[method] FROM unnest(ARRAY['oidc', 'saml', 'pwd']) AS methods(method);
		INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, expires_at)
		SELECT 'rft_legacy_' || id, id, 'rtf_legacy_' || id, token_hash, expires_at FROM sessions;
	`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Migrate(ctx, database.OwnerURL); err != nil {
			t.Fatal(err)
		}
	}
	var enterpriseRevoked, independentActive, guessedOrigin int
	if err := owner.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE s.auth_methods && ARRAY['oidc', 'saml']::text[]
				AND s.revoked_at IS NOT NULL AND r.revoked_at IS NOT NULL),
			count(*) FILTER (WHERE s.auth_methods = ARRAY['pwd']::text[]
				AND s.revoked_at IS NULL AND r.revoked_at IS NULL),
			count(*) FILTER (WHERE s.sso_member_id IS NOT NULL)
		FROM sessions s JOIN refresh_tokens r ON s.id = r.session_id
	`).Scan(&enterpriseRevoked, &independentActive, &guessedOrigin); err != nil {
		t.Fatal(err)
	}
	if enterpriseRevoked != 2 || independentActive != 1 || guessedOrigin != 0 {
		t.Fatalf("migration got enterprise revoked=%d, independent active=%d, inferred origin=%d", enterpriseRevoked, independentActive, guessedOrigin)
	}
}
