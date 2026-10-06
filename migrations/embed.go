package migrations

import "embed"

// FS is the canonical migration set used by sqlc and the runtime migrator.
//
//go:embed *.sql
var FS embed.FS
