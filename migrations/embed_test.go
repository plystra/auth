package migrations

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreForwardOnly(t *testing.T) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no embedded migrations")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			data, err := fs.ReadFile(FS, entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(data), "\n")
			up, down := false, false
			for _, line := range lines {
				line = strings.TrimSpace(line)
				switch line {
				case "-- +goose Up":
					up = true
					continue
				case "-- +goose Down":
					down = true
					continue
				}
				if down && line != "" && !strings.HasPrefix(line, "--") {
					t.Fatalf("Down section contains an executable statement: %q", line)
				}
			}
			if !up {
				t.Fatal("migration has no Up section")
			}
		})
	}
}
