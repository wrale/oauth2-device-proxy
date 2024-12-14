package templates

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
)

//go:embed html/*.html
var content embed.FS

// Templates manages the HTML templates
type Templates struct {
	verify   *template.Template
	complete *template.Template
	error    *template.Template
}

// TemplateError represents a template rendering error
type TemplateError struct {
	Cause   error
	Message string
}

func (e *TemplateError) Error() string {
	return fmt.Sprintf("template error: %s: %v", e.Message, e.Cause)
}

func (e *TemplateError) Unwrap() error {
	return e.Cause
}

// LoadTemplates loads and parses all HTML templates
func LoadTemplates() (*Templates, error) {
	t := &Templates{}
	var err error

	// Load verification page template
	if t.verify, err = template.ParseFS(content, "html/verify.html", "html/layout.html"); err != nil {
		return nil, fmt.Errorf("parsing verify template: %w", err)
	}

	// Load complete page template
	if t.complete, err = template.ParseFS(content, "html/complete.html", "html/layout.html"); err != nil {
		return nil, fmt.Errorf("parsing complete template: %w", err)
	}

	// Load error page template
	if t.error, err = template.ParseFS(content, "html/error.html", "html/layout.html"); err != nil {
		return nil, fmt.Errorf("parsing error template: %w", err)
	}

	return t, nil
}

// SafeWriter wraps an http.ResponseWriter to handle template errors
type SafeWriter struct {
	http.ResponseWriter
	templates  *Templates
	written    bool
	statusCode int
}

// NewSafeWriter creates a new SafeWriter
func (t *Templates) NewSafeWriter(w http.ResponseWriter) *SafeWriter {
	return &SafeWriter{
		ResponseWriter: w,
		templates:      t,
		statusCode:     http.StatusOK,
	}
}

// Written returns whether the response has been written to
func (w *SafeWriter) Written() bool {
	return w.written
}

// Write implements io.Writer
func (w *SafeWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(w.statusCode)
	}
	w.written = true
	return w.ResponseWriter.Write(b)
}

// WriteHeader implements http.ResponseWriter
func (w *SafeWriter) WriteHeader(statusCode int) {
	if !w.written {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.ResponseWriter.WriteHeader(statusCode)
		w.written = true
	}
}

// SetStatusCode sets the HTTP status code if not already written
func (w *SafeWriter) SetStatusCode(code int) {
	if !w.written {
		w.statusCode = code
	}
}

// VerifyData holds data for the code verification page
type VerifyData struct {
	PrefilledCode string
	CSRFToken     string
	Error         string
}

// RenderVerify renders the code verification page
func (t *Templates) RenderVerify(w http.ResponseWriter, data VerifyData) error {
	sw := t.NewSafeWriter(w)
	if err := t.executeToWriter(sw, t.verify, data); err != nil {
		t.renderError(w, "Unable to display verification page", err)
		return err
	}
	return nil
}

// CompleteData holds data for the completion page
type CompleteData struct {
	Message string
}

// RenderComplete renders the completion page
func (t *Templates) RenderComplete(w http.ResponseWriter, data CompleteData) error {
	sw := t.NewSafeWriter(w)
	if err := t.executeToWriter(sw, t.complete, data); err != nil {
		t.renderError(w, "Unable to display completion page", err)
		return err
	}
	return nil
}

// ErrorData holds data for the error page
type ErrorData struct {
	Title   string
	Message string
}

// RenderError renders the error page
func (t *Templates) RenderError(w http.ResponseWriter, data ErrorData) error {
	// If this is a SafeWriter, get the underlying ResponseWriter
	if sw, ok := w.(*SafeWriter); ok {
		w = sw.ResponseWriter
	}

	sw := t.NewSafeWriter(w)
	sw.SetStatusCode(http.StatusBadRequest)

	// Try to render the error template
	err := t.executeToWriter(sw, t.error, data)
	if err != nil {
		// If error template fails, fall back to basic error
		http.Error(w, data.Message, http.StatusInternalServerError)
		return &TemplateError{Cause: err, Message: "failed to render error template"}
	}
	return nil
}

// renderError is a helper that creates and renders an error page
func (t *Templates) renderError(w http.ResponseWriter, message string, cause error) error {
	err := t.RenderError(w, ErrorData{
		Title:   "Error",
		Message: message,
	})
	if err != nil {
		// Return a wrapped error that includes both the original cause and the error template failure
		return &TemplateError{
			Cause:   cause,
			Message: fmt.Sprintf("template error with fallback failure: %v", err),
		}
	}
	// Return the original cause wrapped as a template error
	return &TemplateError{
		Cause:   cause,
		Message: "failed to render template",
	}
}

// executeToWriter executes a template to any io.Writer
func (t *Templates) executeToWriter(w io.Writer, tmpl *template.Template, data interface{}) error {
	// Handle HTTP response writer
	if hw, ok := w.(http.ResponseWriter); ok {
		if sw, ok := w.(*SafeWriter); !ok {
			// Wrap raw http.ResponseWriter in SafeWriter
			w = t.NewSafeWriter(hw)
		} else if !sw.Written() {
			// Ensure headers are written
			sw.WriteHeader(sw.statusCode)
		}
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		return &TemplateError{
			Cause:   err,
			Message: "failed to render template",
		}
	}
	return nil
}

// RenderToString renders a template to a string
func (t *Templates) RenderToString(tmpl *template.Template, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := t.executeToWriter(&buf, tmpl, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
