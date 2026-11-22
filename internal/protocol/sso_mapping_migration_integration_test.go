package protocol

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/migrations"
	"github.com/pressly/goose/v3"
)

func TestSSOMappingMigrationPreservesExistingConnectionWithoutInferringConfigurator(t *testing.T) {
	ctx := t.Context()
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
	if _, err := admin.ExecContext(ctx, "GRANT USAGE, CREATE ON SCHEMA public TO plystra_auth_owner"); err != nil {
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
	if _, err := provider.UpTo(ctx, 64); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `INSERT INTO users (id,email,email_normalized,password_hash,status)
		VALUES ('usr_mapping_history','owner@example.test','owner@example.test','unused','active');
		INSERT INTO sso_connections (id,space_id,name,provider,issuer,client_id,redirect_uri,role_mappings)
		SELECT 'con_mapping_history',id,'Legacy workforce','oidc','https://issuer.example.test','existing-client','https://auth.example.test/callback','{"finance":"rol_old_mapping"}'
		FROM spaces WHERE slug='default'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Migrate(ctx, database.OwnerURL); err != nil {
			t.Fatal(err)
		}
	}
	var kept, missingConfigurator bool
	var applied int
	if err := owner.QueryRowContext(ctx, `SELECT status='active' AND role_mappings='{"finance":"rol_old_mapping"}'::jsonb,
		configured_by_user_id IS NULL AND configured_by_member_id IS NULL,
		(SELECT count(*) FROM goose_db_version WHERE version_id=67 AND is_applied)
		FROM sso_connections WHERE id='con_mapping_history'`).Scan(&kept, &missingConfigurator, &applied); err != nil {
		t.Fatal(err)
	}
	if !kept || !missingConfigurator || applied != 1 {
		t.Fatal("upgrade lost a configured mapping, inferred its author or applied more than once")
	}
	_, err = owner.ExecContext(ctx, "UPDATE sso_connections SET configured_by_user_id='usr_mapping_history' WHERE id='con_mapping_history'")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "sso_configurator_user_requires_member" {
		t.Fatalf("database accepted an unbound SSO configurator or used the wrong constraint: %v", err)
	}
}
