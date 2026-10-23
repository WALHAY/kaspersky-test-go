package threat

import (
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
)

type Input struct {
	Name        string
	Type        string
	Severity    string
	Description string
	Tags        []string
}

type Threat struct {
	MD5 string
	Input
	CreatedAt time.Time
	UpdatedAt time.Time
}
