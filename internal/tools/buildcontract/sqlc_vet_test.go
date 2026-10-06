package buildcontract

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plystra/auth/internal/testdb"
)

func TestSQLCVetPreparesQueriesAgainstMigratedPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	harness, err := testdb.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close(context.Background()) })
	database, err := harness.Clone(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	root := repositoryRoot(t)
	config, err := os.ReadFile(filepath.Join(root, "sqlc.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"${PLYSTRA_SQLC_VET_DATABASE_URL}", "sqlc/db-prepare"} {
		if !strings.Contains(string(config), required) {
			t.Fatalf("sqlc.yaml must configure %q", required)
		}
	}
	cmd := exec.CommandContext(ctx, "go", "tool", "sqlc", "vet")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PLYSTRA_SQLC_VET_DATABASE_URL="+database.URL)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlc vet against migrated PostgreSQL: %v\n%s", err, output)
	}
}
