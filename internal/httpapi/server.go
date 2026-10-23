package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	api "github.com/walhay/kaspersky-go/generated"
	"github.com/walhay/kaspersky-go/internal/threat"
)

type Repository interface {
	Get(context.Context, string) (threat.Threat, error)
	Create(context.Context, string, threat.Input) (threat.Threat, error)
	Update(context.Context, string, threat.Input) (threat.Threat, error)
	Ping(context.Context) error
}

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
	s := &server{
		repo:         repo,
		opts:         opts,
		createSchema: spec.Components.Schemas["ThreatCreateRequest"].Value,
		updateSchema: spec.Components.Schemas["ThreatUpdateRequest"].Value,
	}
	return s.observe(s.protect(s.routes())), nil
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
	input := threat.Input{
		Name:     name,
		Type:     string(typ),
		Severity: string(severity),
	}
	if description != nil {
		input.Description = *description
	}
	if tags != nil {
		input.Tags = *tags
	}
	return threat.NormalizeInput(input)
}

func response(value threat.Threat) api.ThreatResponse {
	return api.ThreatResponse{
		Md5:         value.MD5,
		Name:        value.Name,
		Type:        api.ThreatType(value.Type),
		Severity:    api.Severity(value.Severity),
		Description: value.Description,
		Tags:        value.Tags,
		CreatedAt:   &value.CreatedAt,
		UpdatedAt:   &value.UpdatedAt,
	}
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
	_ = json.NewEncoder(w).Encode(value)
}
