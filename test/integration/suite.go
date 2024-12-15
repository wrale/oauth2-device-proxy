package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
	"time"
)

// Configuration for integration tests
const (
	// Service endpoints - using docker-compose exposed ports
	ProxyEndpoint    = "http://localhost:8085" // Updated to match docker-compose config
	KeycloakEndpoint = "http://localhost:8080"
	RedisEndpoint    = "localhost:6379"

	// Timeouts and delays
	ServiceTimeout = 60 * time.Second
	RetryInterval  = 5 * time.Second
)

// TestSuite provides shared functionality for integration tests
type TestSuite struct {
	T      *testing.T
	Client *http.Client
	Ctx    context.Context
}

// NewSuite creates a new test suite with timeout
func NewSuite(t *testing.T) *TestSuite {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), ServiceTimeout)
	t.Cleanup(cancel)

	return &TestSuite{
		T:      t,
		Client: &http.Client{Timeout: 10 * time.Second},
		Ctx:    ctx,
	}
}

// LogRequest dumps an HTTP request for debugging
func (s *TestSuite) LogRequest(req *http.Request) error {
	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return fmt.Errorf("dumping request: %w", err)
	}
	s.T.Logf("\n=== REQUEST ===\n%s\n", dump)
	return nil
}

// LogResponse dumps an HTTP response for debugging
func (s *TestSuite) LogResponse(resp *http.Response) error {
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return fmt.Errorf("dumping response: %w", err)
	}
	s.T.Logf("\n=== RESPONSE ===\n%s\n", dump)
	return nil
}

// DoRequest performs an HTTP request with logging
func (s *TestSuite) DoRequest(req *http.Request) (*http.Response, error) {
	if err := s.LogRequest(req); err != nil {
		return nil, err
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}

	if err := s.LogResponse(resp); err != nil {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("failed to close response body after log error: %v (original error: %w)", closeErr, err)
		}
		return nil, err
	}

	return resp, nil
}

// ReadBody reads and logs response body while preserving it for reuse
func (s *TestSuite) ReadBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("closing response body: %w", err)
	}

	// Log body content
	s.T.Logf("\n=== BODY ===\n%s\n", body)

	// Replace body for future reads
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// WaitForServices waits for all required services to be healthy
func (s *TestSuite) WaitForServices() error {
	services := []struct {
		name     string
		endpoint string
	}{
		{"proxy", ProxyEndpoint + "/health"},
		{"keycloak", KeycloakEndpoint + "/health/ready"},
		// Redis is checked via proxy health endpoint
	}

	ticker := time.NewTicker(RetryInterval)
	defer ticker.Stop()

	for {
		allHealthy := true
		var lastErr error

		for _, svc := range services {
			req, err := http.NewRequestWithContext(s.Ctx, "GET", svc.endpoint, nil)
			if err != nil {
				return fmt.Errorf("creating request for %s: %w", svc.name, err)
			}

			resp, err := s.DoRequest(req)
			if err != nil {
				allHealthy = false
				lastErr = fmt.Errorf("checking %s health: %w", svc.name, err)
				break
			}

			if err := func() error {
				defer func() {
					if closeErr := resp.Body.Close(); closeErr != nil {
						s.T.Logf("Warning: failed to close response body: %v", closeErr)
					}
				}()
				if resp.StatusCode != http.StatusOK {
					body, _ := s.ReadBody(resp)
					return fmt.Errorf("%s returned status %d: %s", svc.name, resp.StatusCode, body)
				}
				return nil
			}(); err != nil {
				allHealthy = false
				lastErr = err
				break
			}
		}

		if allHealthy {
			return nil
		}

		select {
		case <-s.Ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("timeout waiting for services: %w", lastErr)
			}
			return fmt.Errorf("timeout waiting for services")
		case <-ticker.C:
			continue
		}
	}
}

// ExtractCSRFToken extracts CSRF token from HTML response
func (s *TestSuite) ExtractCSRFToken(html string) string {
	if i := strings.Index(html, `name="csrf_token" value="`); i > 0 {
		html = html[i+len(`name="csrf_token" value="`):]
		if i := strings.Index(html, `"`); i > 0 {
			return html[:i]
		}
	}
	s.T.Log("CSRF token not found in HTML response")
	return ""
}

// BuildURL creates a full URL for an endpoint
func (s *TestSuite) BuildURL(base, path string, params map[string]string) string {
	if len(params) == 0 {
		return base + path
	}

	query := make([]string, 0, len(params))
	for k, v := range params {
		query = append(query, fmt.Sprintf("%s=%s", k, v))
	}
	return base + path + "?" + strings.Join(query, "&")
}
