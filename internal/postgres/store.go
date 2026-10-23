package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/walhay/kaspersky-go/internal/threat"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const columns = `md5, name, type, severity, description, tags, created_at, updated_at`

func (s *Store) Get(ctx context.Context, md5 string) (threat.Threat, error) {
	query := `SELECT ` + columns + ` FROM threats WHERE md5 = $1`
	return scan(s.pool.QueryRow(ctx, query, md5))
}

func (s *Store) Create(ctx context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	query := `
		INSERT INTO threats (md5, name, type, severity, description, tags)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + columns

	return scan(s.pool.QueryRow(ctx, query,
		md5,
		input.Name,
		input.Type,
		input.Severity,
		input.Description,
		input.Tags,
	))
}

func (s *Store) Update(ctx context.Context, md5 string, input threat.Input) (threat.Threat, error) {
	query := `
		UPDATE threats
		SET name = $2,
		    type = $3,
		    severity = $4,
		    description = $5,
		    tags = $6,
		    updated_at = GREATEST(clock_timestamp(), updated_at + interval '1 microsecond')
		WHERE md5 = $1
		RETURNING ` + columns

	return scan(s.pool.QueryRow(ctx, query,
		md5,
		input.Name,
		input.Type,
		input.Severity,
		input.Description,
		input.Tags,
	))
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func scan(row pgx.Row) (threat.Threat, error) {
	var result threat.Threat
	err := row.Scan(
		&result.MD5,
		&result.Name,
		&result.Type,
		&result.Severity,
		&result.Description,
		&result.Tags,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, threat.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return threat.Threat{}, threat.ErrConflict
	}
	if err != nil {
		return threat.Threat{}, fmt.Errorf("query threat: %w", err)
	}
	result.CreatedAt = result.CreatedAt.UTC()
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}
