package httpapi

import (
	"net/http"
	"strings"

	api "github.com/walhay/kaspersky-go/generated"
)

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("/", routeNotFound)

	return api.HandlerWithOptions(s, api.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeError(w, http.StatusBadRequest, "Invalid path parameter", err.Error())
		},
	})
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.repo.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Service unavailable", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func routeNotFound(w http.ResponseWriter, r *http.Request) {
	methods := allowedMethods(r.URL.Path)
	if methods == "" {
		writeError(w, http.StatusNotFound, "Route not found", "")
		return
	}

	w.Header().Set("Allow", methods)
	writeError(w, http.StatusMethodNotAllowed, "Method not allowed", "")
}

func allowedMethods(path string) string {
	switch path {
	case "/info":
		return "POST"
	case "/healthz", "/readyz":
		return "GET, HEAD"
	}

	md5, found := strings.CutPrefix(path, "/info/")
	if found && md5 != "" && !strings.Contains(md5, "/") {
		return "GET, HEAD, PUT"
	}
	return ""
}
