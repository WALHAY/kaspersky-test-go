package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/walhay/kaspersky-go/generated"
	"github.com/walhay/kaspersky-go/internal/httpapi"
	"github.com/walhay/kaspersky-go/internal/threat"
)

const key = "01234567890123456789012345678901"
const md5 = "d41d8cd98f00b204e9800998ecf8427e"
const createBody = `{"md5":"D41D8CD98F00B204E9800998ECF8427E","name":" Trojan ","type":"trojan","severity":"high","description":"Steals credentials","tags":[" windows "]}`

type memoryRepository struct {
	mu         sync.Mutex
	records    map[string]threat.Threat
	err        error
	panicOnGet bool
}

func (m *memoryRepository) Get(_ context.Context, id string) (threat.Threat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.panicOnGet {
		panic("unexpected repository panic")
	}
	if m.err != nil {
		return threat.Threat{}, m.err
	}
	value, exists := m.records[id]
	if !exists {
		return threat.Threat{}, threat.ErrNotFound
	}
	return value, nil
}

func (m *memoryRepository) Create(_ context.Context, id string, input threat.Input) (threat.Threat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return threat.Threat{}, m.err
	}
	if _, exists := m.records[id]; exists {
		return threat.Threat{}, threat.ErrConflict
	}
	if m.records == nil {
		m.records = make(map[string]threat.Threat)
	}
	now := time.Now().UTC()
	value := threat.Threat{MD5: id, Input: input, CreatedAt: now, UpdatedAt: now}
	m.records[id] = value
	return value, nil
}

func (m *memoryRepository) Update(_ context.Context, id string, input threat.Input) (threat.Threat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return threat.Threat{}, m.err
	}
	value, exists := m.records[id]
	if !exists {
		return threat.Threat{}, threat.ErrNotFound
	}
	value.Input, value.UpdatedAt = input, value.UpdatedAt.Add(time.Microsecond)
	m.records[id] = value
	return value, nil
}

func (m *memoryRepository) Ping(context.Context) error { return m.err }

func options() httpapi.Options {
	return httpapi.Options{APIKey: key, RateLimit: 100000, MaxBodyBytes: 65536,
		RequestTimeout: time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func newHandler(t *testing.T, repo httpapi.Repository, opts httpapi.Options) http.Handler {
	t.Helper()
	h, err := httpapi.New(repo, opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func request(h http.Handler, method, path, body, apiKey, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-API-Key", apiKey)
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder, status int) api.ThreatResponse {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status=%d, want=%d; body=%s", w.Code, status, w.Body.String())
	}
	var result api.ThreatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	spec, err := api.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if err := spec.Components.Schemas["ThreatResponse"].Value.VisitJSON(raw); err != nil {
		t.Fatalf("response violates contract: %v", err)
	}
	return result
}

func TestThreatLifecycle(t *testing.T) {
	h := newHandler(t, &memoryRepository{}, options())
	w := request(h, "POST", "/info", createBody, key, "application/json")
	created := decodeResponse(t, w, 201)
	if created.Md5 != md5 || created.Name != "Trojan" || created.Tags[0] != "windows" || created.CreatedAt == nil || created.UpdatedAt == nil {
		t.Fatalf("unexpected creation: %+v", created)
	}
	if w.Header().Get("Location") != "/info/"+md5 {
		t.Fatalf("unexpected location: %s", w.Header().Get("Location"))
	}
	if got := request(h, "POST", "/info", createBody, key, "application/json"); got.Code != 409 {
		t.Fatalf("duplicate status=%d", got.Code)
	}
	fetched := decodeResponse(t, request(h, "GET", "/info/"+strings.ToUpper(md5), "", key, ""), 200)
	if fetched.Description != created.Description {
		t.Fatal("record changed during fetch")
	}
	updated := decodeResponse(t, request(h, "PUT", "/info/"+md5,
		`{"name":"Updated","type":"worm","severity":"critical"}`, key, "application/json; charset=utf-8"), 200)
	if updated.Name != "Updated" || updated.Type != api.Worm || updated.Severity != api.Critical || updated.Description != "" || updated.Tags == nil || len(updated.Tags) != 0 {
		t.Fatalf("PUT did not replace fields: %+v", updated)
	}
	if !updated.CreatedAt.Equal(*created.CreatedAt) || !updated.UpdatedAt.After(*created.UpdatedAt) {
		t.Fatal("incorrect timestamp semantics")
	}
	fetched = decodeResponse(t, request(h, "GET", "/info/"+md5, "", key, ""), 200)
	if fetched.Name != updated.Name || len(fetched.Tags) != 0 {
		t.Fatal("updated record was not persisted")
	}
}

func TestInvalidRequests(t *testing.T) {
	valid := `{"md5":"` + md5 + `","name":"Trojan","type":"trojan","severity":"high"}`
	for _, tc := range []struct {
		name, method, path, body, apiKey, contentType string
		status                                        int
	}{
		{"invalid path md5", "GET", "/info/nope", "", key, "", 400},
		{"not found", "GET", "/info/" + md5, "", key, "", 404},
		{"put does not create", "PUT", "/info/" + md5, `{"name":"new","type":"other","severity":"low"}`, key, "application/json", 404},
		{"missing key", "GET", "/info/" + md5, "", "", "", 401},
		{"wrong key", "GET", "/info/" + md5, "", "wrong", "", 401},
		{"missing media type", "POST", "/info", valid, key, "", 415},
		{"wrong media type", "POST", "/info", valid, key, "text/plain", 415},
		{"empty body", "POST", "/info", "", key, "application/json", 400},
		{"malformed body", "POST", "/info", `{`, key, "application/json", 400},
		{"null body", "POST", "/info", `null`, key, "application/json", 400},
		{"array body", "POST", "/info", `[]`, key, "application/json", 400},
		{"multiple bodies", "POST", "/info", valid + ` {}`, key, "application/json", 400},
		{"trailing garbage", "POST", "/info", valid + `garbage`, key, "application/json", 400},
		{"missing fields", "POST", "/info", `{"md5":"` + md5 + `","name":"a"}`, key, "application/json", 400},
		{"unknown field", "POST", "/info", strings.TrimSuffix(valid, "}") + `,"extra":true}`, key, "application/json", 400},
		{"null optional field", "POST", "/info", strings.TrimSuffix(valid, "}") + `,"tags":null}`, key, "application/json", 400},
		{"null required field", "POST", "/info", strings.Replace(valid, `"Trojan"`, `null`, 1), key, "application/json", 400},
		{"blank name", "POST", "/info", strings.Replace(valid, `"Trojan"`, `"   "`, 1), key, "application/json", 400},
		{"bad md5", "POST", "/info", strings.Replace(valid, md5, "invalid", 1), key, "application/json", 400},
		{"invalid enum", "POST", "/info", strings.Replace(valid, `"high"`, `"unknown"`, 1), key, "application/json", 400},
		{"duplicate field", "POST", "/info", strings.TrimSuffix(valid, "}") + `,"name":"second"}`, key, "application/json", 400},
		{"duplicate tag after trim", "POST", "/info", strings.TrimSuffix(valid, "}") + `,"tags":["a"," a "]}`, key, "application/json", 400},
		{"invalid UTF8", "POST", "/info", strings.Replace(valid, "Trojan", string([]byte{0xff}), 1), key, "application/json", 400},
		{"NUL", "POST", "/info", strings.Replace(valid, "Trojan", `a\u0000b`, 1), key, "application/json", 400},
		{"immutable md5 in put", "PUT", "/info/" + md5, valid, key, "application/json", 400},
		{"unknown route", "GET", "/missing", "", key, "", 404},
		{"wrong method", "DELETE", "/info/" + md5, "", key, "", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(t, &memoryRepository{}, options())
			w := request(h, tc.method, tc.path, tc.body, tc.apiKey, tc.contentType)
			if w.Code != tc.status {
				t.Fatalf("status=%d, want=%d; body=%s", w.Code, tc.status, w.Body.String())
			}
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				t.Fatal("error must be JSON")
			}
			var result api.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Message == "" {
				t.Fatalf("invalid error body: %s", w.Body.String())
			}
		})
	}
}

func TestBodyLimit(t *testing.T) {
	opts := options()
	opts.MaxBodyBytes = 100
	h := newHandler(t, &memoryRepository{}, opts)
	w := request(h, "POST", "/info", createBody, key, "application/json")
	if w.Code != 413 {
		t.Fatalf("status=%d; body=%s", w.Code, w.Body.String())
	}
}

func TestRateLimitAndHealth(t *testing.T) {
	opts := options()
	opts.RateLimit = 1
	h := newHandler(t, &memoryRepository{}, opts)
	if w := request(h, "GET", "/info/"+md5, "", "wrong", ""); w.Code != 401 {
		t.Fatalf("status=%d", w.Code)
	}
	w := request(h, "GET", "/info/"+md5, "", key, "")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected rate limit with Retry-After, got %d", w.Code)
	}
	spoofed := httptest.NewRequest("GET", "/info/"+md5, nil)
	spoofed.Header.Set("X-API-Key", key)
	spoofed.Header.Set("X-Forwarded-For", "203.0.113.99")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, spoofed)
	if w.Code != 429 {
		t.Fatalf("forwarded header bypassed the rate limit: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/info/"+md5, nil)
	r.RemoteAddr = "203.0.113.5:1000"
	r.Header.Set("X-API-Key", key)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("another IP should have its own limit: %d", w.Code)
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if w := request(h, "GET", path, "", "", ""); w.Code != 200 {
			t.Fatalf("%s status=%d", path, w.Code)
		}
	}
}

func TestInternalErrorsAreHidden(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT"} {
		t.Run(method, func(t *testing.T) {
			repo := &memoryRepository{err: errors.New("database password=do-not-expose")}
			h := newHandler(t, repo, options())
			path, body := "/info/"+md5, `{"name":"a","type":"other","severity":"low"}`
			if method == "POST" {
				path, body = "/info", createBody
			}
			w := request(h, method, path, body, key, "application/json")
			if w.Code != 500 || strings.Contains(w.Body.String(), "do-not-expose") {
				t.Fatalf("unsafe response: %d %s", w.Code, w.Body.String())
			}
			if w := request(h, "GET", "/readyz", "", "", ""); w.Code != 503 {
				t.Fatalf("readiness status=%d", w.Code)
			}
		})
	}
	h := newHandler(t, &memoryRepository{panicOnGet: true}, options())
	w := request(h, "GET", "/info/"+md5, "", key, "")
	if w.Code != 500 {
		t.Fatalf("panic response=%d", w.Code)
	}
}

func TestInvalidServerOptions(t *testing.T) {
	for _, change := range []func(*httpapi.Options){
		func(o *httpapi.Options) { o.APIKey = "short" },
		func(o *httpapi.Options) { o.RateLimit = 0 },
		func(o *httpapi.Options) { o.MaxBodyBytes = 0 },
		func(o *httpapi.Options) { o.RequestTimeout = 0 },
	} {
		opts := options()
		change(&opts)
		if _, err := httpapi.New(&memoryRepository{}, opts); err == nil {
			t.Fatal("expected invalid options error")
		}
	}
}
