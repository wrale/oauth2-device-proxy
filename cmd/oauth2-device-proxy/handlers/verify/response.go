// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"fmt"
	"log"
	"net/http"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// headerWritten checks if response headers have been written by checking for
// the Written() method that both SafeWriter and common middleware wrappers implement
func headerWritten(w http.ResponseWriter) bool {
	type writeTracker interface {
		Written() bool
	}

	// Check for SafeWriter or any other writer that tracks header state
	if wt, ok := w.(writeTracker); ok {
		return wt.Written()
	}

	// Default to assuming headers not written if we can't determine
	return false
}

// writeResponse writes a response safely with proper status code per RFC 8628
func (h *Handler) writeResponse(w http.ResponseWriter, status int, message string) {
	// Always set status before writing per RFC 8628
	if !headerWritten(w) {
		w.WriteHeader(status)
	}

	if _, err := w.Write([]byte(message)); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// renderError handles error page rendering with proper status code per RFC 8628
func (h *Handler) renderError(w http.ResponseWriter, status int, title, message string) {
	// Status must be set before any writing per RFC 8628
	w.WriteHeader(status)

	if err := h.templates.RenderError(w, templates.ErrorData{
		Title:   title,
		Message: message,
	}); err != nil {
		log.Printf("Failed to render error page: %v", err)
		// Headers already sent, use plain text fallback
		h.writeResponse(w, status, fmt.Sprintf("%s: %s", title, message))
	}
}

// renderVerify handles verify form rendering per RFC 8628 section 3.3
func (h *Handler) renderVerify(w http.ResponseWriter, data templates.VerifyData) {
	// Form display always returns 200 OK per RFC 8628 section 3.3
	w.WriteHeader(http.StatusOK)

	if err := h.templates.RenderVerify(w, data); err != nil {
		log.Printf("Failed to render verify page: %v", err)
		// Always show form on errors per RFC 8628 3.3
		h.writeResponse(w, http.StatusOK,
			"Please enter your device code to continue.")
	}
}
