package verify

import (
	"net/http"
	"sync"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// mockTemplates provides template rendering functionality for tests per RFC 8628 section 3.3
type mockTemplates struct {
	// Mock function fields
	renderVerify   func(w http.ResponseWriter, data templates.VerifyData) error
	renderError    func(w http.ResponseWriter, data templates.ErrorData) error
	renderComplete func(w http.ResponseWriter, data templates.CompleteData) error

	// Backing templates implementation
	templates *templates.Templates

	// Thread safety for concurrent tests
	mu sync.RWMutex
}

// newMockTemplates creates a new mock templates instance
func newMockTemplates() *mockTemplates {
	return &mockTemplates{
		templates: &templates.Templates{}, // Initialize empty template set per RFC 8628
	}
}

// ToTemplates returns the mock as a *templates.Templates instance
func (m *mockTemplates) ToTemplates() *templates.Templates {
	return m.templates
}

// ImplementsTemplates verifies mock implements all Templates methods per RFC 8628 section 3.3
func (m *mockTemplates) ImplementsTemplates() templates.Templates {
	return *m.templates
}

// RenderVerify follows RFC 8628 section 3.3 user interaction requirements
func (m *mockTemplates) RenderVerify(w http.ResponseWriter, data templates.VerifyData) error {
	m.mu.RLock()
	fn := m.renderVerify
	m.mu.RUnlock()

	if fn != nil {
		return fn(w, data)
	}
	return m.templates.RenderVerify(w, data)
}

// RenderError follows RFC 8628 section 3.3 user interaction requirements
func (m *mockTemplates) RenderError(w http.ResponseWriter, data templates.ErrorData) error {
	m.mu.RLock()
	fn := m.renderError
	m.mu.RUnlock()

	if fn != nil {
		return fn(w, data)
	}
	return m.templates.RenderError(w, data)
}

// RenderComplete follows RFC 8628 section 3.3 user interaction requirements
func (m *mockTemplates) RenderComplete(w http.ResponseWriter, data templates.CompleteData) error {
	m.mu.RLock()
	fn := m.renderComplete
	m.mu.RUnlock()

	if fn != nil {
		return fn(w, data)
	}
	return m.templates.RenderComplete(w, data)
}

// GenerateQRCode follows RFC 8628 section 3.3.1 for verification_uri_complete
func (m *mockTemplates) GenerateQRCode(uri string) (string, error) {
	return "", nil // Provide empty QR code for tests
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
