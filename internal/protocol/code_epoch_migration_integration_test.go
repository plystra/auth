package protocol

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/migrations"
	"github.com/pressly/goose/v3"
)

func TestAuthorizationCodeEpochMigrationPreservesUnboundLegacyCodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	database, err := protocolDB.CloneEmpty(ctx)
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
	dbsql, err := sql.Open("pgx", database.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dbsql.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, dbsql, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 53); err != nil {
		t.Fatal(err)
	}
	if _, err := dbsql.ExecContext(ctx, `INSERT INTO users (id, email, email_normalized, password_hash, status)
		VALUES ('usr_epoch_legacy', 'epoch-legacy@example.test', 'epoch-legacy@example.test', 'test-hash', 'active');
		INSERT INTO members (id, space_id, name, type, binding_policy, status)
		SELECT 'mem_epoch_legacy', id, 'Legacy code member', 'human', 'single', 'active' FROM spaces WHERE slug = 'default';
		INSERT INTO authorization_codes (id, application_id, user_id, member_id, redirect_uri, code_hash, scope, expires_at)
		SELECT 'cod_epoch_legacy', id, 'usr_epoch_legacy', 'mem_epoch_legacy', 'https://client.test/callback',
		decode(repeat('ab', 32), 'hex'), 'auth.members:read', clock_timestamp() + interval '5 minutes'
		FROM applications WHERE client_id = 'default'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Migrate(ctx, database.OwnerURL); err != nil {
			t.Fatal(err)
		}
	}
	var epoch sql.NullInt64
	var memberID string
	var applied int
	var hashPreserved bool
	if err := dbsql.QueryRowContext(ctx, `SELECT c.member_token_epoch, c.member_id,
		c.code_hash = decode(repeat('ab', 32), 'hex'),
		(SELECT count(*) FROM goose_db_version WHERE version_id = 54 AND is_applied)
		FROM authorization_codes c WHERE c.id = 'cod_epoch_legacy'`).Scan(&epoch, &memberID, &hashPreserved, &applied); err != nil {
		t.Fatal(err)
	}
	if epoch.Valid || memberID != "mem_epoch_legacy" || !hashPreserved || applied != 1 {
		t.Fatal("migration invented a legacy issue-time epoch, lost the record, or applied twice")
	}
}

func TestAuthorizationCodeEpochConstraintRejectsInvalidGeneration(t *testing.T) {
	f := newRedemptionFixture(t)
	ctx := context.Background()
	for _, invalid := range []int64{0, -1} {
		_, err := f.store.Pool.Exec(ctx, `UPDATE authorization_codes SET member_token_epoch = $1 WHERE id = 'cod_redemption'`, invalid)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatalf("database accepted an invalid authorization-code generation: error=%v", err)
		}
	}
	if out := f.request(ctx, f.form("authorization_code")); out.Code != http.StatusOK {
		t.Fatalf("constraint rejection changed the valid authorization code: status=%d", out.Code)
	}
}
