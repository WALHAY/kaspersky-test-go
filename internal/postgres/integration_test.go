//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/walhay/kaspersky-go/api"
	"github.com/walhay/kaspersky-go/internal/httpapi"
	"github.com/walhay/kaspersky-go/internal/postgres"
	"github.com/walhay/kaspersky-go/internal/threat"
)

func database(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("TEST_DATABASE_URL is required with -tags=integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "test_" + hex.EncodeToString(random[:])
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("clean schema: %v", err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	testURL := parsed.String()
	if err := postgres.Migrate(ctx, testURL); err != nil {
		t.Fatal(err)
	}
	if err := postgres.Migrate(ctx, testURL); err != nil {
		t.Fatalf("migration must be idempotent: %v", err)
	}
	pool, err := pgxpool.New(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, testURL
}

func TestPostgresHTTPIntegration(t *testing.T) {
	pool, _ := database(t)
	repo := postgres.New(pool)
	const key = "integration-key-01234567890123456789"
	h, err := httpapi.New(repo, httpapi.Options{APIKey: key, RateLimit: 10000, MaxBodyBytes: 65536,
		RequestTimeout: 5 * time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	client := &http.Client{Timeout: 10 * time.Second}
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	createBody := `{"md5":"D41D8CD98F00B204E9800998ECF8427E","name":"Trojan","type":"trojan","severity":"high","description":"description","tags":["windows"]}`
	type result struct {
		status int
		body   []byte
		err    error
	}
	call := func(method, path, body string) result {
		req, err := http.NewRequest(method, srv.URL+path, bytes.NewBufferString(body))
		if err != nil {
			return result{err: err}
		}
		req.Header.Set("X-API-Key", key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return result{err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(resp.Body)
		return result{status: resp.StatusCode, body: data, err: err}
	}
	decode := func(r result, status int) api.ThreatResponse {
		t.Helper()
		if r.err != nil || r.status != status {
			t.Fatalf("response=%d %s err=%v; want=%d", r.status, r.body, r.err, status)
		}
		var value api.ThreatResponse
		if err := json.Unmarshal(r.body, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	results := make(chan result, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { results <- call("POST", "/info", createBody) })
	}
	wg.Wait()
	close(results)
	createdCount, conflictCount := 0, 0
	var created api.ThreatResponse
	for r := range results {
		if r.err != nil {
			t.Fatal(r.err)
		}
		switch r.status {
		case 201:
			createdCount++
			created = decode(r, 201)
		case 409:
			conflictCount++
		default:
			t.Fatalf("unexpected concurrent create: %d %s", r.status, r.body)
		}
	}
	if createdCount != 1 || conflictCount != 15 {
		t.Fatalf("creates=%d conflicts=%d", createdCount, conflictCount)
	}
	fetched := decode(call("GET", "/info/D41D8CD98F00B204E9800998ECF8427E", ""), 200)
	if fetched.Md5 != md5 || fetched.Description != "description" || len(fetched.Tags) != 1 {
		t.Fatalf("unexpected record: %+v", fetched)
	}
	updated := decode(call("PUT", "/info/"+md5, `{"name":"Worm","type":"worm","severity":"critical"}`), 200)
	if updated.Name != "Worm" || updated.Description != "" || updated.Tags == nil || len(updated.Tags) != 0 {
		t.Fatalf("unexpected replacement: %+v", updated)
	}
	if updated.CreatedAt == nil || created.CreatedAt == nil || !updated.CreatedAt.Equal(*created.CreatedAt) || updated.UpdatedAt == nil || !updated.UpdatedAt.After(*created.UpdatedAt) {
		t.Fatal("timestamps are incorrect")
	}
	fetched = decode(call("GET", "/info/"+md5, ""), 200)
	if fetched.Name != "Worm" || fetched.Description != "" || len(fetched.Tags) != 0 {
		t.Fatal("replacement was not persisted")
	}
	missing := call("PUT", "/info/00000000000000000000000000000000", `{"name":"Missing","type":"other","severity":"low"}`)
	if missing.err != nil || missing.status != 404 {
		t.Fatalf("PUT should not insert: %+v", missing)
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM threats`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if r := call("GET", "/readyz", ""); r.err != nil || r.status != 200 {
		t.Fatalf("readiness=%+v", r)
	}
}

func TestPostgresConstraintsAndCancellation(t *testing.T) {
	pool, _ := database(t)
	repo := postgres.New(pool)
	ctx := context.Background()
	input := threat.Input{Name: "Example", Type: "other", Severity: "low", Tags: []string{}}
	for _, md5 := range []string{"invalid", "D41D8CD98F00B204E9800998ECF8427E"} {
		if _, err := repo.Create(ctx, md5, input); err == nil {
			t.Fatalf("database accepted invalid MD5: %q", md5)
		}
	}
	bad := input
	bad.Severity = "unknown"
	if _, err := repo.Create(ctx, "d41d8cd98f00b204e9800998ecf8427e", bad); err == nil {
		t.Fatal("database accepted invalid severity")
	}
	if _, err := repo.Get(ctx, "00000000000000000000000000000000"); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("missing record: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := repo.Create(cancelled, "d41d8cd98f00b204e9800998ecf8427e", input); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := repo.Create(ctx, "d41d8cd98f00b204e9800998ecf8427e", input); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(ctx, "d41d8cd98f00b204e9800998ecf8427e", input); !errors.Is(err, threat.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	pool.Close()
	if err := repo.Ping(ctx); err == nil {
		t.Fatal("closed pool must fail readiness")
	}
	if _, err := repo.Get(ctx, "d41d8cd98f00b204e9800998ecf8427e"); err == nil {
		t.Fatal("closed pool must fail get")
	}
}
