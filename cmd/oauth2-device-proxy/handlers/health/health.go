package health

import (
	"encoding/json"
	"net/http"

	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

// Handler processes health check requests
type Handler struct {
	flow    deviceflow.Flow // Changed from *deviceflow.Flow to deviceflow.Flow
	version string          // Added version field
}

// Response represents the health check response.
// Note: Version field is omitted when empty per RFC 8628 error response format.
type Response struct {
	Status  string         `json:"status"`
	Version string         `json:"version,omitempty"` // Added Version field
	Details map[string]any `json:"details,omitempty"`
}

// New creates a new health check handler
func New(flow deviceflow.Flow) *Handler { // Changed parameter type
	return &Handler{
		flow:    flow,
		version: "unknown", // Default to unknown version
	}
}

// WithVersion sets the version for health check responses
func (h *Handler) WithVersion(version string) *Handler {
	h.version = version
	return h
}

// ServeHTTP handles health check requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set required headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Initialize response with healthy status
	response := Response{
		Status:  "healthy",
		Details: make(map[string]any),
	}

	// Include version if set
	if h.version != "" {
		response.Version = h.version
	}

	// Check device flow health
	if err := h.flow.CheckHealth(r.Context()); err != nil {
		response.Status = "unhealthy"
		response.Details["device_flow"] = map[string]any{
			"status":  "unhealthy",
			"message": err.Error(),
		}
	} else {
		response.Details["device_flow"] = map[string]any{
			"status": "healthy",
		}
	}

	// Set status code based on overall health
	if response.Status != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Write response with proper error handling per RFC 8628 section 5.2
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error":"server_error","error_description":"Error encoding response"}`,
			http.StatusInternalServerError)
		return
	}
}
