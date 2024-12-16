package verify

import (
	"net/http"
	"sync"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// mockTemplates embeds templates.Templates and overrides methods for testing
type mockTemplates struct {
	// Embed real templates struct for interface compatibility
	*templates.Templates

	// Mock function fields
	renderVerify   func(w http.ResponseWriter, data templates.VerifyData) error
	renderError    func(w http.ResponseWriter, data templates.ErrorData) error
	renderComplete func(w http.ResponseWriter, data templates.CompleteData) error

	// Thread safety for concurrent tests
	mu sync.RWMutex
}

// newMockTemplates creates a new mock templates instance
func newMockTemplates() *mockTemplates {
	return &mockTemplates{}
}

// Override RenderVerify for testing
func (m *mockTemplates) RenderVerify(w http.ResponseWriter, data templates.VerifyData) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.renderVerify != nil {
		return m.renderVerify(w, data)
	}
	// Fall back to base Templates implementation if no mock defined
	if m.Templates != nil {
		return m.Templates.RenderVerify(w, data)
	}
	return nil
}

// Override RenderError for testing
func (m *mockTemplates) RenderError(w http.ResponseWriter, data templates.ErrorData) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.renderError != nil {
		return m.renderError(w, data)
	}
	// Fall back to base Templates implementation if no mock defined
	if m.Templates != nil {
		return m.Templates.RenderError(w, data)
	}
	return nil
}

// Override RenderComplete for testing
func (m *mockTemplates) RenderComplete(w http.ResponseWriter, data templates.CompleteData) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.renderComplete != nil {
		return m.renderComplete(w, data)
	}
	// Fall back to base Templates implementation if no mock defined
	if m.Templates != nil {
		return m.Templates.RenderComplete(w, data)
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
