package verify

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"sync"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// mockTemplates provides template rendering functionality for tests per RFC 8628 section 3.3
type mockTemplates struct {
	// Core templates for rendering
	tmpl *template.Template

	// Mock function fields
	renderVerify   func(w http.ResponseWriter, data templates.VerifyData) error
	renderError    func(w http.ResponseWriter, data templates.ErrorData) error
	renderComplete func(w http.ResponseWriter, data templates.CompleteData) error
	generateQR     func(uri string) (string, error)

	// Thread safety for concurrent tests
	mu sync.RWMutex
}

// newMockTemplates creates a new mock templates instance with default templates
func newMockTemplates() *mockTemplates {
	// Create initial template set for defaults
	tmpl := template.Must(template.New("mock").Parse(`
{{define "verify"}}
<!DOCTYPE html>
<html><body>{{printf "Verify: %+v" .}}</body></html>
{{end}}

{{define "error"}}
<!DOCTYPE html>
<html><body>{{printf "Error: %+v" .}}</body></html>
{{end}}

{{define "complete"}}
<!DOCTYPE html>
<html><body>{{printf "Complete: %+v" .}}</body></html>
{{end}}
`))

	return &mockTemplates{
		tmpl: tmpl,
	}
}

// ToTemplates returns this mock as a properly initialized *templates.Templates
func (m *mockTemplates) ToTemplates() *templates.Templates {
	t := &templates.Templates{}

	// Init with base templates
	t.InitTemplates(m.tmpl)

	// Override render functions
	t.RenderVerifyFunc = func(w http.ResponseWriter, data templates.VerifyData) error {
		return m.RenderVerify(w, data)
	}
	t.RenderErrorFunc = func(w http.ResponseWriter, data templates.ErrorData) error {
		return m.RenderError(w, data)
	}
	t.RenderCompleteFunc = func(w http.ResponseWriter, data templates.CompleteData) error {
		return m.RenderComplete(w, data)
	}
	t.GenerateQRCodeFunc = func(uri string) (string, error) {
		return m.GenerateQRCode(uri)
	}

	return t
}

// RenderVerify follows RFC 8628 section 3.3 user interaction requirements
func (m *mockTemplates) RenderVerify(w http.ResponseWriter, data templates.VerifyData) error {
	m.mu.RLock()
	fn := m.renderVerify
	m.mu.RUnlock()

	if fn != nil {
		return fn(w, data)
	}
	return m.defaultRender(w, "verify", data)
}

// RenderError follows RFC 8628 section 3.3 user interaction requirements
func (m *mockTemplates) RenderError(w http.ResponseWriter, data templates.ErrorData) error {
	m.mu.RLock()
	fn := m.renderError
	m.mu.RUnlock()

	if fn != nil {
		return fn(w, data)
	}
	return m.defaultRender(w, "error", data)
}

// RenderComplete follows RFC 8628 section 3.3 user interaction requirements
func (m *mockTemplates) RenderComplete(w http.ResponseWriter, data templates.CompleteData) error {
	m.mu.RLock()
	fn := m.renderComplete
	m.mu.RUnlock()

	if fn != nil {
		return fn(w, data)
	}
	return m.defaultRender(w, "complete", data)
}

// GenerateQRCode follows RFC 8628 section 3.3.1 for verification_uri_complete
func (m *mockTemplates) GenerateQRCode(uri string) (string, error) {
	m.mu.RLock()
	fn := m.generateQR
	m.mu.RUnlock()

	if fn != nil {
		return fn(uri)
	}
	return "", nil // Default empty QR code for tests
}

// WithRenderVerify sets the mock RenderVerify function while maintaining thread safety
func (m *mockTemplates) WithRenderVerify(fn func(w http.ResponseWriter, data templates.VerifyData) error) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renderVerify = fn
	return m
}

// WithRenderError sets the mock RenderError function while maintaining thread safety
func (m *mockTemplates) WithRenderError(fn func(w http.ResponseWriter, data templates.ErrorData) error) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renderError = fn
	return m
}

// WithRenderComplete sets the mock RenderComplete function while maintaining thread safety
func (m *mockTemplates) WithRenderComplete(fn func(w http.ResponseWriter, data templates.CompleteData) error) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renderComplete = fn
	return m
}

// WithGenerateQRCode sets the mock GenerateQRCode function while maintaining thread safety
func (m *mockTemplates) WithGenerateQRCode(fn func(uri string) (string, error)) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generateQR = fn
	return m
}

// defaultRender uses the pre-initialized templates to handle rendering
func (m *mockTemplates) defaultRender(w http.ResponseWriter, name string, data interface{}) error {
	// Create safe writer if needed
	if _, ok := w.(*templates.SafeWriter); !ok {
		w = &templates.SafeWriter{
			ResponseWriter: w,
			StatusCode:     http.StatusOK,
		}
	}

	// Set content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Render template to buffer first
	var buf bytes.Buffer
	if err := m.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return &templates.TemplateError{
			Cause:   err,
			Message: "failed to execute template",
			Code:    http.StatusInternalServerError,
		}
	}

	// Write the result
	if _, err := io.Copy(w, &buf); err != nil {
		return &templates.TemplateError{
			Cause:   err,
			Message: "failed to write response",
			Code:    http.StatusInternalServerError,
		}
	}

	return nil
}
