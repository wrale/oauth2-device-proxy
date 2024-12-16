// Package verify provides verification flow handlers per RFC 8628 section 3.3
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
	mock := &mockTemplates{}

	// Set default mock QR code generator per RFC 8628 section 3.3.1
	mock.generateQR = func(uri string) (string, error) {
		return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
			<title>Test QR Code</title>
			<rect width="100" height="100" fill="white"/>
			<rect x="25" y="25" width="50" height="50"/>
		</svg>`, nil
	}

	// Create base template with layout
	base := template.Must(template.New("layout").Parse(`<!DOCTYPE html><html><body>{{template "content" .}}</body></html>`))

	// Add templates
	template.Must(base.New("verify-title").Parse(`Verify Device`))
	template.Must(base.New("verify-content").Parse(`
		{{if .VerificationQRCodeSVG}}
			<div class="qr-code">{{.VerificationQRCodeSVG}}</div>
		{{end}}
		<form method="post">
			<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
			<input type="text" name="code" value="{{.PrefilledCode}}">
			<button type="submit">Verify</button>
		</form>
	`))
	template.Must(base.New("verify").Parse(`{{template "layout" .}}`))

	template.Must(base.New("error-title").Parse(`Error`))
	template.Must(base.New("error-content").Parse(`Error: {{.Message}}`))
	template.Must(base.New("error").Parse(`{{template "layout" .}}`))

	template.Must(base.New("complete-title").Parse(`Success`))
	template.Must(base.New("complete-content").Parse(`{{.Message}}`))
	template.Must(base.New("complete").Parse(`{{template "layout" .}}`))

	mock.tmpl = base

	// Initialize templates
	mock.templates.SetVerify(base)
	mock.templates.SetError(base)
	mock.templates.SetComplete(base)

	return mock
}

// ToTemplates returns this mock as a properly initialized *templates.Templates
func (m *mockTemplates) ToTemplates() *templates.Templates {
	t := &templates.Templates{}

	t.SetVerify(m.tmpl)
	t.SetComplete(m.tmpl)
	t.SetError(m.tmpl)

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

	// Return static test QR code per RFC 8628 section 3.3.1
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
		<title>Default Test QR Code</title>
		<rect width="100" height="100" fill="white"/>
		<rect x="25" y="25" width="50" height="50"/>
	</svg>`, nil
}

// WithRenderVerify sets the mock RenderVerify function
func (m *mockTemplates) WithRenderVerify(fn func(w http.ResponseWriter, data templates.VerifyData) error) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renderVerify = fn
	return m
}

// WithRenderError sets the mock RenderError function
func (m *mockTemplates) WithRenderError(fn func(w http.ResponseWriter, data templates.ErrorData) error) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renderError = fn
	return m
}

// WithRenderComplete sets the mock RenderComplete function
func (m *mockTemplates) WithRenderComplete(fn func(w http.ResponseWriter, data templates.CompleteData) error) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renderComplete = fn
	return m
}

// WithGenerateQRCode sets the mock GenerateQRCode function
func (m *mockTemplates) WithGenerateQRCode(fn func(uri string) (string, error)) *mockTemplates {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generateQR = fn
	return m
}

// defaultRender uses the pre-initialized templates for rendering
func (m *mockTemplates) defaultRender(w http.ResponseWriter, name string, data interface{}) error {
	// Set content type per RFC 8628
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Render template
	var buf bytes.Buffer
	if err := m.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return &templates.TemplateError{
			Cause:   err,
			Message: "failed to execute template",
			Code:    http.StatusInternalServerError,
		}
	}

	_, err := io.Copy(w, &buf)
	return err
}
