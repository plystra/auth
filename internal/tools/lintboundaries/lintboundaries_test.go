package lintboundaries

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestArchitectureLintRejectsBoundaryViolations(t *testing.T) {
	if testing.Short() {
		t.Skip("architecture lint requires a separate checkout")
	}
	root := repositoryRoot(t)
	checkout := filepath.Join(t.TempDir(), "auth-lint-checkout")
	worktree := exec.Command("git", "worktree", "add", "--detach", checkout, "HEAD")
	worktree.Dir = root
	if output, err := worktree.CombinedOutput(); err != nil {
		t.Fatalf("create lint worktree: %v\n%s", err, output)
	}
	t.Cleanup(func() {
		remove := exec.Command("git", "worktree", "remove", "--force", checkout)
		remove.Dir = root
		if output, err := remove.CombinedOutput(); err != nil {
			t.Errorf("remove lint worktree: %v\n%s", err, output)
		}
	})
	// Validate the configuration under test even before it has been committed.
	config, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, ".golangci.yml"), config, 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		path        string
		source      string
		packagePath string
		want        string
	}{
		{
			name:        "pure authorization import",
			path:        "internal/authz/engine/lint_boundary_probe.go",
			source:      "package engine\nimport \"os\"\nvar lintBoundaryProbe = os.Getenv(\"PROBE\")\n",
			packagePath: "./internal/authz/engine",
			want:        "(depguard)",
		},
		{
			name:        "pure authorization clock",
			path:        "internal/authz/delta/lint_boundary_probe.go",
			source:      "package delta\nimport \"time\"\nfunc lintBoundaryProbe() time.Time {\n return time.Now()\n}\n",
			packagePath: "./internal/authz/delta",
			want:        "(forbidigo)",
		},
		{
			name:        "interaction plane dependency",
			path:        "internal/plane/principal/lint_boundary_probe.go",
			source:      "package principal\nimport _ \"github.com/plystra/auth/internal/plane/ops\"\n",
			packagePath: "./internal/plane/principal",
			want:        "(depguard)",
		},
		{
			name:        "server plane dependency",
			path:        "internal/plane/server/lint_boundary_probe.go",
			source:      "package server\nimport _ \"github.com/plystra/auth/internal/plane/ops\"\n",
			packagePath: "./internal/plane/server",
			want:        "(depguard)",
		},
		{
			name:        "ops plane dependency",
			path:        "internal/plane/ops/lint_boundary_probe.go",
			source:      "package ops\nimport _ \"github.com/plystra/auth/internal/plane/principal\"\n",
			packagePath: "./internal/plane/ops",
			want:        "(depguard)",
		},
		{
			name:        "route registration outside route package",
			path:        "internal/store/lint_boundary_probe.go",
			source:      "package store\nimport (\"context\"; \"github.com/danielgtaylor/huma/v2\")\nfunc lintBoundaryProbe[I,O any](api huma.API, handler func(context.Context,*I)(*O,error)) {\n huma.Register(api, huma.Operation{Method:\"GET\", Path:\"/lint-boundary-probe\"}, handler)\n}\n",
			packagePath: "./internal/store",
			want:        "(forbidigo)",
		},
		{
			name:        "transaction outside store package",
			path:        "internal/route/lint_boundary_probe.go",
			source:      "package route\nimport (\"context\"; \"github.com/jackc/pgx/v5/pgxpool\")\nfunc lintBoundaryProbe(ctx context.Context, p *pgxpool.Pool) {\n _, _ = p.Begin(ctx)\n}\n",
			packagePath: "./internal/route",
			want:        "(forbidigo)",
		},
		{
			name:        "Agent management bypasses transactional authorization",
			path:        "internal/plane/principal/lint_boundary_probe.go",
			source:      "package principal\nimport (\"context\"; \"github.com/plystra/auth/internal/agent\")\nfunc lintBoundaryProbe(ctx context.Context, svc *agent.Service) {\n _, _, _ = svc.Create(ctx, agent.CreateInput{})\n}\n",
			packagePath: "./internal/plane/principal",
			want:        "use managed Agent lifecycle methods for transactional authorization",
		},
		{
			name:        "application management bypasses actor and target locks",
			path:        "internal/application/lint_boundary_probe.go",
			source:      "package application\nimport (\"context\"; \"github.com/plystra/auth/internal/authorization\"; \"github.com/plystra/auth/internal/db\")\nfunc lintBoundaryProbe(ctx context.Context, svc *authorization.Service, q *db.Queries) {\n _, _ = svc.CheckTx(ctx, q, authorization.CheckRequest{})\n}\n",
			packagePath: "./internal/application",
			want:        "application management must use CheckNodeTx",
		},
		{
			name:        "application management uses standalone authorization",
			path:        "internal/application/lint_boundary_probe.go",
			source:      "package application\nimport (\"context\"; authz \"github.com/plystra/auth/internal/authorization\")\nfunc lintBoundaryProbe(ctx context.Context, svc *authz.Service) {\n _, _, _ = svc.Check(ctx, authz.CheckRequest{})\n}\n",
			packagePath: "./internal/application",
			want:        "application management must use CheckNodeTx",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe := filepath.Join(checkout, filepath.FromSlash(tc.path))
			if err := os.WriteFile(probe, []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.Remove(probe); err != nil {
					t.Errorf("remove lint probe: %v", err)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "tool", "golangci-lint", "run", tc.packagePath)
			cmd.Dir = checkout
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), tc.want) {
				t.Fatalf("lint result = %v, want %s diagnostic\n%s", err, tc.want, output)
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}
