package store

import _ "embed"

//go:embed migrations/001_init.sql
var initSQL string

//go:embed migrations/002_captures.sql
var capturesSQL string

var migrations = []string{initSQL, capturesSQL}
