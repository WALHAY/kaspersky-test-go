// Package config reads and validates environment-based service configuration.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr       string
	DatabaseURL    string
	APIKey         string
	RateLimit      int
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	TLSCertFile    string
	TLSKeyFile     string
}

// Load refuses to start without a database URL or a sufficiently long API key.
func Load() (Config, error) {
	return read(os.Getenv)
}

func read(getenv func(string) string) (Config, error) {
	cfg := Config{HTTPAddr: ":8080", DatabaseURL: getenv("DATABASE_URL"), APIKey: getenv("API_KEY"),
		RateLimit: 60, MaxBodyBytes: 64 * 1024, RequestTimeout: 5 * time.Second,
		TLSCertFile: getenv("TLS_CERT_FILE"), TLSKeyFile: getenv("TLS_KEY_FILE")}
	if value := getenv("HTTP_ADDR"); value != "" {
		cfg.HTTPAddr = value
	}
	if _, _, err := net.SplitHostPort(cfg.HTTPAddr); err != nil {
		return Config{}, fmt.Errorf("HTTP_ADDR must be host:port")
	}
	parsed, err := url.Parse(cfg.DatabaseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		return Config{}, fmt.Errorf("DATABASE_URL must be a PostgreSQL connection URL")
	}
	if len(cfg.APIKey) < 32 || strings.TrimSpace(cfg.APIKey) != cfg.APIKey {
		return Config{}, fmt.Errorf("API_KEY must contain at least 32 bytes without surrounding whitespace")
	}
	if value := getenv("RATE_LIMIT_PER_MINUTE"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100000 {
			return Config{}, fmt.Errorf("RATE_LIMIT_PER_MINUTE must be between 1 and 100000")
		}
		cfg.RateLimit = n
	}
	if value := getenv("MAX_BODY_BYTES"); value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 1 || n > 1024*1024 {
			return Config{}, fmt.Errorf("MAX_BODY_BYTES must be between 1 and 1048576")
		}
		cfg.MaxBodyBytes = n
	}
	if value := getenv("REQUEST_TIMEOUT"); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil || d < time.Millisecond || d > 30*time.Second {
			return Config{}, fmt.Errorf("REQUEST_TIMEOUT must be between 1ms and 30s")
		}
		cfg.RequestTimeout = d
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE must be set together")
	}
	return cfg, nil
}
