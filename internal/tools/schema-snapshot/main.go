package main

import (
	"os"
	"path/filepath"
	"strings"
)

func main() {
	data, err := os.ReadFile("migrations/0001_init.sql")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "-- +goose") || strings.HasPrefix(strings.TrimSpace(line), "-- +goose") || strings.TrimSpace(line) == "-- +goose Down" {
			continue
		}
		out = append(out, line)
	}
	if err := os.MkdirAll("schema", 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join("schema", "schema.sql"), []byte(strings.Join(out, "\n")), 0644); err != nil {
		panic(err)
	}
}
