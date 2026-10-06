package buildcontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeCheckContainsRequiredGates(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(data)
	for _, required := range []string{
		"check: gen",
		"git diff --exit-code",
		"$(MAKE) web-check",
		"$(GO) tool golangci-lint run",
		"$(GO) test -race ./...",
		"$(GO) tool govulncheck ./...",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile is missing check gate %q", required)
		}
	}
	if !strings.Contains(makefile, "web-check:") || !strings.Contains(makefile, "bun run typecheck") || !strings.Contains(makefile, "bun run test --run") {
		t.Error("Makefile is missing the frontend typecheck and test gate")
	}
}

func TestRepositoryModuleAndLayoutMatchTechStack(t *testing.T) {
	root := repositoryRoot(t)
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"module github.com/plystra/auth", "go 1.26"} {
		if !strings.Contains(string(goMod), required) {
			t.Errorf("go.mod is missing %q", required)
		}
	}
	for _, directory := range []string{
		"cmd/plystra-auth",
		"internal/route",
		"internal/plane/principal",
		"internal/plane/server",
		"internal/plane/ops",
		"internal/authz/engine",
		"internal/authz/delta",
		"migrations",
		"schema",
		"openapi",
	} {
		if info, statErr := os.Stat(filepath.Join(root, directory)); statErr != nil || !info.IsDir() {
			t.Errorf("tech-stack directory %q is missing", directory)
		}
	}
}

func TestEngineeringToolsArePinnedAndBoundaryRulesAreConfigured(t *testing.T) {
	root := repositoryRoot(t)
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{
		"github.com/sqlc-dev/sqlc/cmd/sqlc",
		"github.com/pressly/goose/v3/cmd/goose",
		"github.com/golangci/golangci-lint/v2/cmd/golangci-lint",
		"golang.org/x/vuln/cmd/govulncheck",
		"github.com/riverqueue/river/cmd/river",
	} {
		if !strings.Contains(string(goMod), tool) {
			t.Errorf("go.mod tool directive is missing %q", tool)
		}
	}
	config, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		"- depguard",
		"- forbidigo",
		"huma\\.Register",
		"Begin(Tx)?",
		"time\\.Now",
		"authz_pure:",
		"principal_plane:",
		"server_plane:",
		"ops_plane:",
	} {
		if !strings.Contains(string(config), rule) {
			t.Errorf(".golangci.yml is missing boundary rule %q", rule)
		}
	}
}

func TestCIChecksMinimumAndLatestPostgresImages(t *testing.T) {
	root := repositoryRoot(t)
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "check.yml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(workflow)
	for _, required := range []string{
		"PLYSTRA_TEST_POSTGRES_IMAGE: postgres:${{ matrix.postgres }}-alpine",
		"postgres: [17, 18]",
		"run: make check",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("CI workflow is missing %q", required)
		}
	}
}

func TestAgentsGuideMapsChangesToSourcesAndVerification(t *testing.T) {
	root := repositoryRoot(t)
	guide, err := os.ReadFile(filepath.Join(root, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(guide)
	for _, required := range []string{
		"../auth-docs/tech-stack.md",
		"migrations/",
		"internal/<domain>/queries/",
		"route.Register",
		"make gen",
		"make check",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("AGENTS.md is missing change-map entry %q", required)
		}
	}
}

func TestMakeDevUsesDockerComposeDevelopmentStack(t *testing.T) {
	root := repositoryRoot(t)
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(filepath.Join(root, "docker-compose.dev.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"dev:", "docker compose -f docker-compose.dev.yml up --build"} {
		if !strings.Contains(string(makefile), required) {
			t.Errorf("Makefile is missing dev entry %q", required)
		}
	}
	for _, required := range []string{"postgres:17-alpine", "condition: service_healthy", "plystra-auth migrate", "PLYSTRA_AUTH_ENVIRONMENT: development"} {
		if !strings.Contains(string(compose), required) {
			t.Errorf("development compose file is missing %q", required)
		}
	}
}

func TestTestDBUsesDockerTemplateDatabaseClones(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "internal", "testdb", "testdb.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"testcontainers-go/modules/postgres",
		"postgres.Run(ctx, image",
		"PLYSTRA_TEST_POSTGRES_IMAGE",
		"CREATE DATABASE ",
		" TEMPLATE ",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("test database harness is missing %q", required)
		}
	}
}

func TestRepositoryPublishesLicenseAndSecurityPolicy(t *testing.T) {
	root := repositoryRoot(t)
	license, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(license), "Apache License") || !strings.Contains(string(license), "END OF TERMS AND CONDITIONS") {
		t.Fatal("LICENSE is not the Apache-2.0 text")
	}
	security, err := os.ReadFile(filepath.Join(root, "SECURITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"GitHub Security", "Advisory", "3 business days", "7 business days", "14 days"} {
		if !strings.Contains(string(security), required) {
			t.Errorf("SECURITY.md is missing %q", required)
		}
	}
}

func TestGeneratedOpenAPIDocumentsAreCommitted(t *testing.T) {
	root := repositoryRoot(t)
	for _, name := range []string{"principal.json", "server.json", "ops.json"} {
		path := filepath.Join(root, "openapi", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var document struct {
			OpenAPI string                     `json:"openapi"`
			Info    map[string]json.RawMessage `json:"info"`
			Paths   map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if document.OpenAPI != "3.1.0" {
			t.Errorf("%s OpenAPI version = %q, want 3.1.0", name, document.OpenAPI)
		}
		if len(document.Info) == 0 {
			t.Errorf("%s is missing the OpenAPI info object", name)
		}
		if len(document.Paths) == 0 {
			t.Errorf("%s contains no generated paths", name)
		}
	}
}

func TestSQLCUsesMigrationSchemaAndGeneratedDBOutput(t *testing.T) {
	root := repositoryRoot(t)
	config, err := os.ReadFile(filepath.Join(root, "sqlc.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(config)
	for _, required := range []string{
		"schema: \"migrations\"",
		"out: \"internal/db\"",
		"internal/account/queries",
		"internal/session/queries",
		"internal/space/queries",
		"internal/audit/queries",
		"internal/application/queries",
		"internal/agent",
		"internal/factor",
		"internal/member",
		"internal/grant",
		"internal/store",
		"internal/operator/queries",
		"internal/idempotency",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("sqlc.yaml is missing %q", required)
		}
	}
	for _, path := range []string{
		"internal/db/db.go",
		"internal/db/models.go",
		"internal/db/queries.sql.go",
	} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Errorf("generated sqlc output %s is missing: %v", path, err)
		}
	}
}

func TestSchemaSnapshotContainsMigrationDerivedAuthorizationTables(t *testing.T) {
	root := repositoryRoot(t)
	snapshot, err := os.ReadFile(filepath.Join(root, "schema", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(snapshot)
	for _, required := range []string{
		"CREATE TABLE permissions",
		"status text NOT NULL DEFAULT 'active'",
		"CREATE TABLE IF NOT EXISTS authorization_grants",
		"CREATE TABLE audit_logs",
		"CREATE TABLE idempotency_keys",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("schema snapshot is missing %q", required)
		}
	}
}

func TestOnlyStoreOwnsTransactionEntry(t *testing.T) {
	root := repositoryRoot(t)
	internalRoot := filepath.Join(root, "internal")
	err := filepath.Walk(internalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") || strings.Contains(path, string(filepath.Separator)+"store"+string(filepath.Separator)) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		source := string(data)
		if strings.Contains(source, "Begin(") || strings.Contains(source, "BeginTx(") {
			t.Errorf("%s opens a transaction directly; use store.InTx", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("could not find repository root")
		}
		root = parent
	}
}
