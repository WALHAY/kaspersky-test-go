// Package threat defines threat records and validation independent of HTTP and storage.
package threat

import (
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
)

// Input contains all replaceable fields. Empty Description and Tags clear existing values.
type Input struct {
	Name        string
	Type        string
	Severity    string
	Description string
	Tags        []string
}

// Threat is a stored record. Its MD5 and creation time never change.
type Threat struct {
	MD5 string
	Input
	CreatedAt time.Time
	UpdatedAt time.Time
}
