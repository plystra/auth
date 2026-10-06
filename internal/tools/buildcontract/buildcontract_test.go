package buildcontract

import (
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
		"$(GO) tool golangci-lint run",
		"$(GO) test -race ./...",
		"$(GO) tool govulncheck ./...",
	} {
		if !strings.Contains(makefile, required) {
			t.Errorf("Makefile is missing check gate %q", required)
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
