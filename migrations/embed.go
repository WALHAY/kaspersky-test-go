// Package migrations embeds versioned goose SQL migrations into the executable.
package migrations

import "embed"

// Files is the migration filesystem used by the migration command.
//
//go:embed *.sql
var Files embed.FS
