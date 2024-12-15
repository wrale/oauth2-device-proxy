package health

import (
	"encoding/json"
	"net/http"
)

// Response represents the health check response format
type Response struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Handler provides health check functionality
type Handler struct {
	version   string
	checkFunc func() error
}

// New creates a new health check handler
func New(version string, checkFunc func() error) *Handler {
	return &Handler{
		version:   version,
		checkFunc: checkFunc,
	}
}

// ServeHTTP implements the health check endpoint
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set required headers for JSON response
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")

	// Build response
	resp := Response{
		Status:  "ok",
		Version: h.version,
	}

	// Check system health
	if err := h.checkFunc(); err != nil {
		resp.Status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Encode response
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, `{"status":"error","error":"encoding_failed"}`, http.StatusInternalServerError)
		return
	}
}
