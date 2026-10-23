package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3"
)

func (s *server) decode(w http.ResponseWriter, r *http.Request, schema *openapi3.Schema, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Unsupported media type", "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "Request body too large", "")
		} else {
			writeError(w, http.StatusBadRequest, "Cannot read request body", "")
		}
		return false
	}
	if !utf8.Valid(data) {
		writeError(w, http.StatusBadRequest, "Invalid JSON", "Body must be valid UTF-8")
		return false
	}
	if err := validateObject(data); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
		return false
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON", "Malformed JSON body")
		return false
	}
	if err := schema.VisitJSON(value); err != nil {
		// Avoid echoing a full request (which may contain sensitive information) in schema errors.
		var schemaError *openapi3.SchemaError
		details := "Body does not match the OpenAPI schema"
		if errors.As(err, &schemaError) {
			details = schemaError.Reason
		}
		writeError(w, http.StatusBadRequest, "Invalid request", details)
		return false
	}
	if err := json.Unmarshal(data, target); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON", "Malformed JSON body")
		return false
	}
	return true
}

// validateObject rejects duplicate keys and multiple JSON values before schema validation.
// The contract only permits scalar values and an array of strings in this object.
func validateObject(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("body must be a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("malformed JSON body")
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("malformed JSON key")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = struct{}{}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return errors.New("malformed JSON body")
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("malformed JSON body")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("body must contain exactly one JSON object")
	}
	return nil
}
