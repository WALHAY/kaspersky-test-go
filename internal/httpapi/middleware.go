package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// windowLimiter bounds both request counts and memory. A full client map rejects
// new clients until the next window, instead of evicting active rate limits.
type windowLimiter struct {
	mu     sync.Mutex
	start  time.Time
	counts map[string]int
	limit  int
}

func (l *windowLimiter) allow(client string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts == nil || now.Sub(l.start) >= time.Minute {
		l.start = now
		l.counts = make(map[string]int)
	}
	retry := max(1, int(math.Ceil(time.Minute.Seconds()-now.Sub(l.start).Seconds())))
	count, exists := l.counts[client]
	if count >= l.limit || (!exists && len(l.counts) >= 10000) {
		return false, retry
	}
	l.counts[client] = count + 1
	return true, 0
}

func (s *server) protect(next http.Handler) http.Handler {
	expected := sha256.Sum256([]byte(s.opts.APIKey))
	limiter := &windowLimiter{limit: s.opts.RateLimit}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.URL.Path == "/info" || strings.HasPrefix(r.URL.Path, "/info/") {
			client, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				client = r.RemoteAddr
			}
			if allowed, retry := limiter.allow(client, time.Now()); !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				writeError(w, http.StatusTooManyRequests, "Rate limit exceeded", "")
				return
			}
			provided := sha256.Sum256([]byte(r.Header.Get("X-API-Key")))
			if subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
				writeError(w, http.StatusUnauthorized, "Unauthorized", "A valid X-API-Key is required")
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.opts.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		writer := &statusWriter{ResponseWriter: w}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.opts.Logger.ErrorContext(r.Context(), "request panic", "panic", recovered)
				if writer.status == 0 {
					writeError(writer, http.StatusInternalServerError, "Internal server error", "")
				}
			}
			status := writer.status
			if status == 0 {
				status = http.StatusOK
			}
			s.opts.Logger.InfoContext(r.Context(), "http request", "method", r.Method,
				"path", r.URL.Path, "status", status, "duration", time.Since(start))
		}()
		next.ServeHTTP(writer, r)
	})
}
