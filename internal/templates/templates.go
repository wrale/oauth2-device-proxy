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
	templates *Templates
	written   bool
}

// NewSafeWriter creates a new SafeWriter
func (t *Templates) NewSafeWriter(w http.ResponseWriter) *SafeWriter {
	return &SafeWriter{
		ResponseWriter: w,
		templates:      t,
	}
}

// Write implements io.Writer
func (w *SafeWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

// WriteHeader implements http.ResponseWriter
func (w *SafeWriter) WriteHeader(statusCode int) {
	if !w.written {
		w.ResponseWriter.WriteHeader(statusCode)
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
	if err := t.verify.ExecuteTemplate(sw, "layout", data); err != nil {
		return t.renderError(w, "Unable to display verification page", err)
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
	if err := t.complete.ExecuteTemplate(sw, "layout", data); err != nil {
		return t.renderError(w, "Unable to display completion page", err)
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

	// Ensure headers haven't been written
	if sw, ok := w.(interface{ Written() bool }); !ok || !sw.Written() {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
	}

	// Try to render the error template
	err := t.error.ExecuteTemplate(w, "layout", data)
	if err != nil {
		// If error template fails, fall back to basic error
		http.Error(w, data.Message, http.StatusInternalServerError)
		return &TemplateError{Cause: err, Message: "failed to render error template"}
	}
	return nil
}

// renderError is a helper that creates and renders an error page
func (t *Templates) renderError(w http.ResponseWriter, message string, cause error) error {
	return t.RenderError(w, ErrorData{
		Title:   "Error",
		Message: message,
	})
}

// executeToWriter executes a template to any io.Writer
func (t *Templates) executeToWriter(w io.Writer, tmpl *template.Template, data interface{}) error {
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		return &TemplateError{Cause: err, Message: "failed to render template"}
	}
	return nil
}

// RenderToString renders a template to a string, using io.Writer for template execution
func (t *Templates) RenderToString(tmpl *template.Template, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := t.executeToWriter(&buf, tmpl, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
