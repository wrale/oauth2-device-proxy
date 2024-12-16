package health

import (
	"encoding/json"
	"net/http"

	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

// Handler processes health check requests
type Handler struct {
	flow deviceflow.Flow // Changed from *deviceflow.Flow to deviceflow.Flow
}

// Response represents the health check response
type Response struct {
	Status  string         `json:"status"`
	Details map[string]any `json:"details,omitempty"`
}

// New creates a new health check handler
func New(flow deviceflow.Flow) *Handler { // Changed parameter type
	return &Handler{
		flow: flow,
	}
}

// ServeHTTP handles health check requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Initialize response with healthy status
	response := Response{
		Status:  "healthy",
		Details: make(map[string]any),
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

	// Write response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "error encoding response", http.StatusInternalServerError)
	}
}
