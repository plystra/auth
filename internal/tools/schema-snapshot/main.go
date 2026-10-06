package main

import (
	"os"
	"path/filepath"
	"strings"
)

func main() {
	paths, err := filepath.Glob("migrations/*.sql")
	if err != nil {
		panic(err)
	}
	var out []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "-- +goose Down" {
				break
			}
			if strings.HasPrefix(strings.TrimSpace(line), "-- +goose") {
				continue
			}
			out = append(out, line)
		}
	}
	if err := os.MkdirAll("schema", 0755); err != nil {
		panic(err)
	}
	contents := strings.TrimSuffix(strings.Join(out, "\n"), "\n")
	if err := os.WriteFile(filepath.Join("schema", "schema.sql"), []byte(contents), 0644); err != nil {
		panic(err)
	}
}
