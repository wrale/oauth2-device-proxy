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

			if err := func() error {
				defer func() {
					if closeErr := resp.Body.Close(); closeErr != nil {
						s.T.Logf("Error closing response body for %s: %v", svc.name, closeErr)
					}
				}()

				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("%s returned status %d", svc.name, resp.StatusCode)
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