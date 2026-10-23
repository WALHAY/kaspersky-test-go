package threat

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// NormalizeMD5 validates the identifier and makes uniqueness case-insensitive.
func NormalizeMD5(value string) (string, error) {
	if !md5Pattern.MatchString(value) {
		return "", fmt.Errorf("md5 must contain exactly 32 hexadecimal characters")
	}
	return strings.ToLower(value), nil
}

// NormalizeInput trims names and tags, validates limits in Unicode characters,
// and rejects NUL characters which PostgreSQL text cannot store.
func NormalizeInput(input Input) (Input, error) {
	if err := validateText("name", input.Name, 255); err != nil {
		return Input{}, err
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" {
		return Input{}, fmt.Errorf("name must not be blank")
	}
	switch input.Type {
	case "trojan", "virus", "worm", "ransomware", "spyware", "adware", "rootkit", "other":
	default:
		return Input{}, fmt.Errorf("type must be trojan, virus, worm, ransomware, spyware, adware, rootkit or other")
	}
	switch input.Severity {
	case "low", "medium", "high", "critical":
	default:
		return Input{}, fmt.Errorf("severity must be low, medium, high or critical")
	}
	if err := validateText("description", input.Description, 4096); err != nil {
		return Input{}, err
	}
	if len(input.Tags) > 20 {
		return Input{}, fmt.Errorf("tags must contain at most 20 items")
	}
	tags := make([]string, 0, len(input.Tags))
	seen := make(map[string]struct{}, len(input.Tags))
	for _, tag := range input.Tags {
		if err := validateText("tag", tag, 64); err != nil {
			return Input{}, err
		}
		tag = strings.TrimSpace(tag)
		if tag == "" {
			return Input{}, fmt.Errorf("tags must not be blank")
		}
		if _, exists := seen[tag]; exists {
			return Input{}, fmt.Errorf("tags must be unique after trimming")
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	input.Tags = tags
	return input, nil
}

func validateText(field, value string, maxLength int) error {
	if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s must be valid UTF-8 without NUL characters", field)
	}
	if utf8.RuneCountInString(value) > maxLength {
		return fmt.Errorf("%s must contain at most %d characters", field, maxLength)
	}
	return nil
}
