package application

import (
	"database/sql"
	"testing"

	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/migrations"
	"github.com/pressly/goose/v3"
)

func TestHumanOIDCMigrationLeavesExistingClientsDisabled(t *testing.T) {
	ctx := t.Context()
	database, err := applicationDB.CloneEmpty(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close(ctx) }()
	admin, err := sql.Open("pgx", database.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	if _, err := admin.ExecContext(ctx, "GRANT USAGE, CREATE ON SCHEMA public TO plystra_auth_owner"); err != nil {
		t.Fatal(err)
	}
	owner, err := sql.Open("pgx", database.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	provider, err := goose.NewProvider(goose.DialectPostgres, owner, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 63); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `INSERT INTO applications (id, space_id, name, client_id)
		SELECT 'app_before_login', id, 'Existing client', 'existing-client' FROM spaces WHERE slug='default'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Migrate(ctx, database.OwnerURL); err != nil {
			t.Fatal(err)
		}
	}
	var allDisabled bool
	if err := owner.QueryRowContext(ctx, `SELECT count(*)=2 AND bool_and(human_oidc_enabled IS FALSE)
		FROM applications WHERE client_id IN ('default','existing-client')`).Scan(&allDisabled); err != nil || !allDisabled {
		t.Fatal("an upgraded client was missing or implicitly opted into OIDC", err)
	}
}
