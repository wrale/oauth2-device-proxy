package verify

import (
	"net/http"
	"sync"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// mockTemplates embeds templates.Templates and overrides methods for testing.
// All methods follow RFC 8628 section 3.3 for user interaction requirements.
type mockTemplates struct {
	// Embed real templates struct to properly implement interface
	templates.Templates

	// Mock function fields
	renderVerify   func(w http.ResponseWriter, data templates.VerifyData) error
	renderError    func(w http.ResponseWriter, data templates.ErrorData) error
	renderComplete func(w http.ResponseWriter, data templates.CompleteData) error

	// Thread safety for concurrent tests
	mu sync.RWMutex
}

// newMockTemplates creates a new mock templates instance
func newMockTemplates() *mockTemplates {
	// Required empty template set per section 3.3
	return &mockTemplates{}
}

// RenderVerify renders verification page per RFC 8628 section 3.3
func (m *mockTemplates) RenderVerify(w http.ResponseWriter, data templates.VerifyData) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.renderVerify != nil {
		return m.renderVerify(w, data)
	}
	return nil
}

// RenderError renders error page per RFC 8628 section 3.3
func (m *mockTemplates) RenderError(w http.ResponseWriter, data templates.ErrorData) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.renderError != nil {
		return m.renderError(w, data)
	}
	return nil
}

// RenderComplete renders completion page per RFC 8628 section 3.3
func (m *mockTemplates) RenderComplete(w http.ResponseWriter, data templates.CompleteData) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.renderComplete != nil {
		return m.renderComplete(w, data)
	}
	return nil
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
