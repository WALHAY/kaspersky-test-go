package config

import (
	"testing"
	"time"
)

func TestConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
	}{
		{"database missing", "DATABASE_URL", ""},
		{"wrong scheme", "DATABASE_URL", "http://localhost/db"},
		{"malformed database", "DATABASE_URL", "postgres://%xx"},
		{"short key", "API_KEY", "secret"},
		{"whitespace key", "API_KEY", "                                "},
		{"address", "HTTP_ADDR", "8080"},
		{"zero limit", "RATE_LIMIT_PER_MINUTE", "0"},
		{"invalid limit", "RATE_LIMIT_PER_MINUTE", "a"},
		{"negative body limit", "MAX_BODY_BYTES", "-1"},
		{"huge body limit", "MAX_BODY_BYTES", "1048577"},
		{"invalid timeout", "REQUEST_TIMEOUT", "invalid"},
		{"zero timeout", "REQUEST_TIMEOUT", "0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"DATABASE_URL": "postgres://user:pass@localhost/threats", "API_KEY": "01234567890123456789012345678901"}
			env[tc.key] = tc.value
			if _, err := read(func(k string) string { return env[k] }); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}

	env := map[string]string{"DATABASE_URL": "postgres://user:pass@localhost/threats", "API_KEY": "01234567890123456789012345678901"}
	cfg, err := read(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.RateLimit != 60 || cfg.MaxBodyBytes != 65536 || cfg.RequestTimeout != 5*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	env["HTTP_ADDR"], env["RATE_LIMIT_PER_MINUTE"], env["MAX_BODY_BYTES"], env["REQUEST_TIMEOUT"] = "127.0.0.1:9090", "120", "1024", "2s"
	cfg, err = read(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9090" || cfg.RateLimit != 120 || cfg.MaxBodyBytes != 1024 || cfg.RequestTimeout != 2*time.Second {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
}
