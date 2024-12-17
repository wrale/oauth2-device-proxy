// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"fmt"
	"log"
	"net/http"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// responseWriter wraps http.ResponseWriter to ensure proper header handling per RFC 8628
type responseWriter struct {
	http.ResponseWriter
	headerWritten bool
	statusCode    int
	contentType   string
}

// newResponseWriter creates a new responseWriter
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // Default per RFC 8628 section 3.3
		contentType:    "text/html; charset=utf-8",
	}
}

// Written returns true if headers have been written
func (w *responseWriter) Written() bool {
	return w.headerWritten
}

// WriteHeader implements http.ResponseWriter per RFC 8628
func (w *responseWriter) WriteHeader(code int) {
	if !w.headerWritten {
		w.statusCode = code
		w.Header().Set("Content-Type", w.contentType)
		w.ResponseWriter.WriteHeader(code)
		w.headerWritten = true
	}
}

// Write implements io.Writer per RFC 8628
func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(w.statusCode)
	}
	return w.ResponseWriter.Write(b)
}

// SetContentType sets the Content-Type before headers are written
func (w *responseWriter) SetContentType(contentType string) {
	if !w.headerWritten {
		w.contentType = contentType
	}
}

// renderError handles error page rendering per RFC 8628 section 3.3
func (h *Handler) renderError(w http.ResponseWriter, status int, title, message string) {
	// Wrap the writer to ensure proper header handling
	rw := newResponseWriter(w)

	// Set status before any writing per RFC 8628
	rw.WriteHeader(status)

	// Render template with wrapped writer
	if err := h.templates.RenderError(rw, templates.ErrorData{
		Title:   title,
		Message: message,
	}); err != nil {
		log.Printf("Failed to render error page: %v", err)
		// Writer ensures proper header state
		h.writeResponse(rw, status, fmt.Sprintf("%s: %s", title, message))
	}
}

// renderVerify handles verify form rendering per RFC 8628 section 3.3
func (h *Handler) renderVerify(w http.ResponseWriter, data templates.VerifyData) {
	// Wrap the writer to ensure proper header handling
	rw := newResponseWriter(w)

	// Always return 200 OK for form display per RFC 8628 section 3.3
	rw.WriteHeader(http.StatusOK)

	if err := h.templates.RenderVerify(rw, data); err != nil {
		log.Printf("Failed to render verify page: %v", err)
		// Headers already set, use plain text fallback
		h.writeResponse(rw, http.StatusOK,
			"Please enter your device code to continue.")
	}
}

// writeResponse writes a response safely per RFC 8628
func (h *Handler) writeResponse(w http.ResponseWriter, status int, message string) {
	// Ensure we have a properly wrapped writer
	rw, ok := w.(*responseWriter)
	if !ok {
		rw = newResponseWriter(w)
	}

	// Set plain text content type for direct responses
	rw.SetContentType("text/plain; charset=utf-8")

	// Always set status before writing per RFC 8628
	if !rw.Written() {
		rw.WriteHeader(status)
	}

	if _, err := rw.Write([]byte(message)); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
