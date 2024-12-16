package verify

import (
	"bytes"
	"fmt"
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

	// Mock templates instance for creating SafeWriters
	templates templates.Templates
}

// newMockTemplates creates a new mock templates instance with default templates
func newMockTemplates() *mockTemplates {
	// Create base template with layout first
	base := template.Must(template.New("layout").Parse(`<!DOCTYPE html><html><body>{{template "content" .}}</body></html>`))

	// Add verify template
	template.Must(base.New("verify-title").Parse(`Verify Device`))
	template.Must(base.New("verify-content").Parse(`Verify: {{printf "%+v" .}}`))
	template.Must(base.New("verify").Parse(`{{template "layout" .}}`))

	// Add error template
	template.Must(base.New("error-title").Parse(`Error`))
	template.Must(base.New("error-content").Parse(`Error: {{printf "%+v" .}}`))
	template.Must(base.New("error").Parse(`{{template "layout" .}}`))

	// Add complete template
	template.Must(base.New("complete-title").Parse(`Complete`))
	template.Must(base.New("complete-content").Parse(`Complete: {{printf "%+v" .}}`))
	template.Must(base.New("complete").Parse(`{{template "layout" .}}`))

	mock := &mockTemplates{
		tmpl: base,
		// Set default mock QR code generator for tests that don't override it
		generateQR: func(uri string) (string, error) {
			// Create simple test QR code SVG - this just needs to be valid SVG
			// The real QR code implementation is in internal/templates/qrcode.go
			return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
				<title>Test QR for %s</title>
				<rect width="100" height="100" fill="white"/>
				<rect x="25" y="25" width="50" height="50"/>
			</svg>`, uri), nil
		},
	}

	// Initialize templates for proper SafeWriter creation
	mock.templates.SetVerify(base)
	mock.templates.SetError(base)
	mock.templates.SetComplete(base)

	return mock
}

// ToTemplates returns this mock as a properly initialized *templates.Templates
func (m *mockTemplates) ToTemplates() *templates.Templates {
	t := &templates.Templates{}

	// Directly initialize template fields
	t.SetVerify(m.tmpl)
	t.SetComplete(m.tmpl)
	t.SetError(m.tmpl)

	// Set mock functions for rendering
	t.SetRenderVerifyFunc(func(w http.ResponseWriter, data templates.VerifyData) error {
		return m.RenderVerify(w, data)
	})
	t.SetRenderErrorFunc(func(w http.ResponseWriter, data templates.ErrorData) error {
		return m.RenderError(w, data)
	})
	t.SetRenderCompleteFunc(func(w http.ResponseWriter, data templates.CompleteData) error {
		return m.RenderComplete(w, data)
	})
	t.SetGenerateQRCodeFunc(func(uri string) (string, error) {
		return m.GenerateQRCode(uri)
	})

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
	// Return empty SVG by default
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"/>`, nil
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
	// Create safe writer using proper NewSafeWriter constructor
	sw := m.templates.NewSafeWriter(w)
	sw.SetStatusCode(http.StatusOK) // Set default status for tests

	// Set content type
	sw.Header().Set("Content-Type", "text/html; charset=utf-8")

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
	if _, err := io.Copy(sw, &buf); err != nil {
		return &templates.TemplateError{
			Cause:   err,
			Message: "failed to write response",
			Code:    http.StatusInternalServerError,
		}
	}

	return nil
}
