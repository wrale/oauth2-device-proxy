package templates

import (
	"net/http"
)

// mockResponseWriter implements http.ResponseWriter for testing
type mockResponseWriter struct {
	written     []byte
	headers     http.Header
	statusCode  int
	writeCount  int
	headersSent bool
}

func newMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{
		headers: make(http.Header),
	}
}

func (m *mockResponseWriter) Header() http.Header {
	return m.headers
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	if !m.headersSent {
		m.WriteHeader(http.StatusOK)
	}
	m.written = append(m.written, b...)
	m.writeCount++
	return len(b), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	if !m.headersSent {
		m.statusCode = statusCode
		m.headersSent = true
	}
}

// Written returns the accumulated written bytes as a string
func (m *mockResponseWriter) Written() string {
	return string(m.written)
}

// Contains checks if the written content contains all the given strings
func (m *mockResponseWriter) Contains(ss ...string) bool {
	content := m.Written()
	for _, s := range ss {
		if !strings.Contains(content, s) {
			return false
		}
	}
	return true
}

// setupTemplates creates a new Templates instance for testing
func setupTemplates(t *testing.T) *Templates {
	t.Helper()
	templates, err := LoadTemplates()
	if err != nil {
		t.Fatalf("failed to load templates: %v", err)
	}
	return templates
}
