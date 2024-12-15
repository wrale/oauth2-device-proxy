package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Configuration for integration tests
const (
	// Service endpoints
	ProxyEndpoint    = "http://localhost:8080"
	KeycloakEndpoint = "http://localhost:8081"
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

			resp, err := s.Client.Do(req)
			if err != nil {
				allHealthy = false
				lastErr = fmt.Errorf("checking %s health: %w", svc.name, err)
				break
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				allHealthy = false
				lastErr = fmt.Errorf("%s returned status %d", svc.name, resp.StatusCode)
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
