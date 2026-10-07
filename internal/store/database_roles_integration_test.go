package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/plystra/auth/internal/store"
	"github.com/plystra/auth/internal/testdb"
)

var _ *testdb.Harness

func TestApplicationRoleCanOnlyInsertAndSelectAuditLogs(t *testing.T) {
	ctx := context.Background()
	database, err := rateLimitDB.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })

	app, err := store.Open(ctx, database.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	var currentRole string
	if err := app.Pool.QueryRow(ctx, "SELECT current_user").Scan(&currentRole); err != nil {
		t.Fatal(err)
	}
	if currentRole != "plystra_auth_app" {
		t.Fatalf("application connection role = %q, want plystra_auth_app", currentRole)
	}
	const auditID = "aud_role_privilege_test"
	if _, err := app.Pool.Exec(ctx, `
		INSERT INTO audit_logs (id, actor_type, action, outcome)
		VALUES ($1, 'test', 'database.role.test', 'success')
	`, auditID); err != nil {
		t.Fatalf("application INSERT audit_logs: %v", err)
	}
	var action string
	if err := app.Pool.QueryRow(ctx, `SELECT action FROM audit_logs WHERE id = $1`, auditID).Scan(&action); err != nil {
		t.Fatalf("application SELECT audit_logs: %v", err)
	}
	if action != "database.role.test" {
		t.Fatalf("audit action = %q", action)
	}
	for _, statement := range []string{
		`UPDATE audit_logs SET action = 'changed' WHERE id = 'aud_role_privilege_test'`,
		`DELETE FROM audit_logs WHERE id = 'aud_role_privilege_test'`,
	} {
		if _, err := app.Pool.Exec(ctx, statement); err == nil {
			t.Fatalf("application role unexpectedly executed %s", statement)
		} else {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("privilege error for %s = %v, want PostgreSQL 42501", statement, err)
			}
		}
	}
}
