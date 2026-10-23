package threat_test

import (
	"strings"
	"testing"

	"github.com/walhay/kaspersky-go/internal/threat"
)

func TestNormalizeMD5(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		invalid           bool
	}{
		{"lowercase", "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"uppercase", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"short", "abc", "", true},
		{"nonhex", strings.Repeat("z", 32), "", true},
		{"whitespace", " d41d8cd98f00b204e9800998ecf8427e", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := threat.NormalizeMD5(tc.input)
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("got %q, %v; want %q, invalid=%v", got, err, tc.want, tc.invalid)
			}
		})
	}
}

func TestNormalizeInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*threat.Input)
	}{
		{"blank name", func(v *threat.Input) { v.Name = " \t\n" }},
		{"long name", func(v *threat.Input) { v.Name = strings.Repeat("я", 256) }},
		{"unknown type", func(v *threat.Input) { v.Type = "unknown" }},
		{"unknown severity", func(v *threat.Input) { v.Severity = "dangerous" }},
		{"long description", func(v *threat.Input) { v.Description = strings.Repeat("я", 4097) }},
		{"too many tags", func(v *threat.Input) { v.Tags = make([]string, 21) }},
		{"blank tag", func(v *threat.Input) { v.Tags = []string{" "} }},
		{"long tag", func(v *threat.Input) { v.Tags = []string{strings.Repeat("я", 65)} }},
		{"duplicate after trim", func(v *threat.Input) { v.Tags = []string{"windows", " windows "} }},
		{"nul in name", func(v *threat.Input) { v.Name = "a\x00b" }},
		{"nul in description", func(v *threat.Input) { v.Description = "\x00" }},
		{"invalid utf8", func(v *threat.Input) { v.Name = string([]byte{0xff}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := threat.Input{Name: "Trojan", Type: "trojan", Severity: "high"}
			tc.change(&v)
			if _, err := threat.NormalizeInput(v); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	v, err := threat.NormalizeInput(threat.Input{
		Name: " Trojan ", Type: "trojan", Severity: "high", Tags: []string{" windows ", "Windows"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "Trojan" || v.Tags[0] != "windows" || v.Tags[1] != "Windows" {
		t.Fatalf("unexpected normalization: %+v", v)
	}
	v, err = threat.NormalizeInput(threat.Input{Name: "я", Type: "other", Severity: "low"})
	if err != nil || v.Tags == nil {
		t.Fatalf("empty tags must be a non-nil slice: %+v, %v", v, err)
	}
}
