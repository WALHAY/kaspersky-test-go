// Package httpapi implements the generated API contract and its HTTP protections.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/walhay/kaspersky-go/api"
	"github.com/walhay/kaspersky-go/internal/threat"
)

// Repository is the persistence contract consumed by the HTTP server.
type Repository interface {
	Get(context.Context, string) (threat.Threat, error)
	Create(context.Context, string, threat.Input) (threat.Threat, error)
	Update(context.Context, string, threat.Input) (threat.Threat, error)
	Ping(context.Context) error
}

// Options controls authentication, resource limits, and logging.
type Options struct {
	APIKey         string
	RateLimit      int
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	Logger         *slog.Logger
}

type server struct {
	repo         Repository
	opts         Options
	createSchema *openapi3.Schema
	updateSchema *openapi3.Schema
}

var _ api.ServerInterface = (*server)(nil)

// New builds a handler using the generated standard-library router.
func New(repo Repository, opts Options) (http.Handler, error) {
	if len(opts.APIKey) < 32 {
		return nil, errors.New("API key must contain at least 32 bytes")
	}
	if opts.RateLimit <= 0 || opts.MaxBodyBytes <= 0 || opts.RequestTimeout <= 0 {
		return nil, errors.New("rate limit, body limit and timeout must be positive")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	spec, err := api.GetSwagger()
	if err != nil {
		return nil, err
	}
	if err := spec.Validate(context.Background()); err != nil {
		return nil, err
	}
	s := &server{repo: repo, opts: opts,
		createSchema: spec.Components.Schemas["ThreatCreateRequest"].Value,
		updateSchema: spec.Components.Schemas["ThreatUpdateRequest"].Value}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), opts.RequestTimeout)
		defer cancel()
		if err := repo.Ping(ctx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "Service unavailable", "")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		allowed := ""
		switch {
		case r.URL.Path == "/info":
			allowed = "POST"
		case strings.HasPrefix(r.URL.Path, "/info/") && len(strings.Split(r.URL.Path, "/")) == 3 && r.URL.Path != "/info/":
			allowed = "GET, HEAD, PUT"
		case r.URL.Path == "/healthz" || r.URL.Path == "/readyz":
			allowed = "GET, HEAD"
		}
		if allowed != "" {
			w.Header().Set("Allow", allowed)
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
			return
		}
		writeError(w, http.StatusNotFound, "Route not found", "")
	})
	handler := api.HandlerWithOptions(s, api.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeError(w, http.StatusBadRequest, "Invalid path parameter", err.Error())
		},
	})
	return s.observe(s.protect(handler)), nil
}

func (s *server) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var body api.ThreatCreateRequest
	if !s.decode(w, r, s.createSchema, &body) {
		return
	}
	md5, err := threat.NormalizeMD5(body.Md5)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	input, err := makeInput(body.Name, body.Type, body.Severity, body.Description, body.Tags)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	result, err := s.repo.Create(r.Context(), md5, input)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/info/"+result.MD5)
	writeJSON(w, http.StatusCreated, response(result))
}

func (s *server) GetInfoByMd5(w http.ResponseWriter, r *http.Request, value api.MD5) {
	md5, err := threat.NormalizeMD5(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid MD5", err.Error())
		return
	}
	result, err := s.repo.Get(r.Context(), md5)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response(result))
}

func (s *server) UpdateThreat(w http.ResponseWriter, r *http.Request, value api.MD5) {
	md5, err := threat.NormalizeMD5(value)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid MD5", err.Error())
		return
	}
	var body api.ThreatUpdateRequest
	if !s.decode(w, r, s.updateSchema, &body) {
		return
	}
	input, err := makeInput(body.Name, body.Type, body.Severity, body.Description, body.Tags)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	result, err := s.repo.Update(r.Context(), md5, input)
	if err != nil {
		s.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, response(result))
}

func makeInput(name string, typ api.ThreatType, severity api.Severity, description *string, tags *[]string) (threat.Input, error) {
	input := threat.Input{Name: name, Type: string(typ), Severity: string(severity)}
	if description != nil {
		input.Description = *description
	}
	if tags != nil {
		input.Tags = *tags
	}
	return threat.NormalizeInput(input)
}

func response(value threat.Threat) api.ThreatResponse {
	return api.ThreatResponse{Md5: value.MD5, Name: value.Name, Type: api.ThreatType(value.Type),
		Severity: api.Severity(value.Severity), Description: value.Description, Tags: value.Tags,
		CreatedAt: &value.CreatedAt, UpdatedAt: &value.UpdatedAt}
}

func (s *server) storeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, threat.ErrNotFound):
		writeError(w, http.StatusNotFound, "Threat not found", "")
	case errors.Is(err, threat.ErrConflict):
		writeError(w, http.StatusConflict, "Threat already exists", "")
	default:
		s.opts.Logger.ErrorContext(r.Context(), "storage request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "Internal server error", "")
	}
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	result := api.ErrorResponse{Message: message}
	if details != "" {
		result.Details = &details
	}
	writeJSON(w, status, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value) // A disconnected client cannot receive a replacement response.
}
