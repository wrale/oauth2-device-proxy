package common

import (
	"encoding/json"
	"net/http"
	"strings"
)

// RFC 8628 Compliant Error Response
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// SetJSONHeaders sets required headers for JSON responses per RFC 8628
func SetJSONHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
}

// WriteError sends a standardized error response per RFC 8628 section 3.5
func WriteError(w http.ResponseWriter, code string, description string) {
	// First set required headers per RFC 8628
	SetJSONHeaders(w)

	response := ErrorResponse{
		Error:            code,
		ErrorDescription: strings.TrimSpace(description),
	}

	// Set status code and write response
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		WriteJSONError(w, err)
		return
	}
}

// WriteJSONError handles JSON encoding failures with a standardized response
func WriteJSONError(w http.ResponseWriter, err error) {
	// Headers must be set here since they weren't set by caller due to error
	SetJSONHeaders(w)
	w.WriteHeader(http.StatusInternalServerError)

	// Create error response manually since JSON encoding failed
	errResponse := []byte(`{"error":"server_error","error_description":"Failed to encode response"}`)
	if _, writeErr := w.Write(errResponse); writeErr != nil {
		// At this point all we can do is log the compound error when we have logging
		return
	}
}
