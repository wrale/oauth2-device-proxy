package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Constants that define behavior specified by RFC 8628
const (
	// DefaultPollingInterval is the minimum polling interval required by RFC 8628 Section 3.2
	// when no interval is provided in the device authorization response
	DefaultPollingInterval = 5 * time.Second

	// MaxPollingAttempts limits how long we'll poll in tests to prevent infinite loops
	MaxPollingAttempts = 30
)

// doDeviceAuthRequest performs a device authorization request as specified in RFC 8628 Section 3.1.
// It sends a POST request to the device authorization endpoint with the provided parameters.
// The function handles all request setup, execution, and response body reading while providing
// detailed logging for test diagnostics.
func doDeviceAuthRequest(t *testing.T, s *TestSuite, params map[string]string) (*http.Response, []byte) {
	t.Helper()

	// Build request body from parameters
	data := url.Values{}
	for k, v := range params {
		data.Set(k, v)
	}

	// Create the HTTP request with proper context and headers
	req, err := http.NewRequestWithContext(s.Ctx, "POST",
		ProxyEndpoint+"/device/code",
		strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Failed to create device authorization request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request and handle response
	resp, err := s.DoRequest(req)
	if err != nil {
		t.Fatalf("Device authorization request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read and return the full response body
	body, err := s.ReadBody(resp)
	if err != nil {
		t.Fatalf("Failed to read device authorization response: %v", err)
	}

	return resp, body
}

// doTokenRequest performs a token request as specified in RFC 8628 Section 3.4.
// It handles the POST request to the token endpoint with appropriate parameters
// and returns both the response and body for validation.
func doTokenRequest(t *testing.T, s *TestSuite, params map[string]string) (*http.Response, []byte) {
	t.Helper()

	data := url.Values{}
	for k, v := range params {
		data.Set(k, v)
	}

	req, err := http.NewRequestWithContext(s.Ctx, "POST",
		ProxyEndpoint+"/device/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Failed to create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.DoRequest(req)
	if err != nil {
		t.Fatalf("Token request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := s.ReadBody(resp)
	if err != nil {
		t.Fatalf("Failed to read token response: %v", err)
	}

	return resp, body
}

// pollForToken implements the token polling behavior specified in RFC 8628 Section 3.5.
// It repeatedly requests a token using the given device code, handling all expected
// error responses and backoff requirements. The function stops when it either receives
// a token, encounters an error that indicates polling should stop (e.g., access_denied),
// or reaches the maximum number of attempts.
func pollForToken(ctx context.Context, t *testing.T, s *TestSuite, auth *deviceAuthResponse) (*tokenResponse, error) {
	t.Helper()

	// Determine polling interval, using RFC-specified default if none provided
	interval := time.Duration(auth.Interval) * time.Second
	if interval == 0 {
		interval = DefaultPollingInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Start polling loop with attempt tracking
	attempt := 0
	for {
		attempt++
		if attempt > MaxPollingAttempts {
			return nil, fmt.Errorf("exceeded maximum polling attempts (%d)", MaxPollingAttempts)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("polling cancelled: %w", ctx.Err())

		case <-ticker.C:
			t.Logf("Token polling attempt %d/%d", attempt, MaxPollingAttempts)

			// Make token request
			resp, body := doTokenRequest(t, s, map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": auth.DeviceCode,
				"client_id":   "test-client",
			})

			// Handle successful token response
			if resp.StatusCode == http.StatusOK {
				var token tokenResponse
				if err := json.Unmarshal(body, &token); err != nil {
					return nil, fmt.Errorf("failed to decode token response: %w", err)
				}
				return &token, nil
			}

			// Parse error response
			var errResp errorResponse
			if err := json.Unmarshal(body, &errResp); err != nil {
				return nil, fmt.Errorf("failed to decode error response: %w", err)
			}

			// Handle different error cases as specified in RFC 8628 Section 3.5
			switch errResp.Error {
			case "authorization_pending":
				t.Log("Authorization pending, continuing to poll...")
				continue

			case "slow_down":
				t.Log("Received slow_down error, increasing polling interval")
				newInterval := interval + (5 * time.Second)
				ticker.Reset(newInterval)
				interval = newInterval
				continue

			case "access_denied":
				return nil, fmt.Errorf("user denied access")

			case "expired_token":
				return nil, fmt.Errorf("device code expired")

			default:
				return nil, fmt.Errorf("unexpected error: %s - %s",
					errResp.Error, errResp.ErrorDescription)
			}
		}
	}
}

// simulateUserVerification simulates a user visiting the verification URI and approving
// the device. This helper encapsulates the user interaction steps described in
// RFC 8628 Section 3.3 for testing purposes.
func simulateUserVerification(s *TestSuite, auth *deviceAuthResponse) error {
	s.T.Log("Simulating user verification flow...")

	// First fetch the verification page to get any required tokens/state
	req, err := http.NewRequestWithContext(s.Ctx, "GET", auth.VerificationURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create verification page request: %w", err)
	}

	resp, err := s.DoRequest(req)
	if err != nil {
		return fmt.Errorf("failed to fetch verification page: %w", err)
	}

	body, err := s.ReadBody(resp)
	if err != nil {
		return fmt.Errorf("failed to read verification page: %w", err)
	}
	resp.Body.Close()

	// Extract CSRF token if present
	csrfToken := s.ExtractCSRFToken(string(body))

	// Submit user code verification
	data := url.Values{
		"code": {auth.UserCode},
	}
	if csrfToken != "" {
		data.Set("csrf_token", csrfToken)
	}

	req, err = http.NewRequestWithContext(s.Ctx, "POST",
		auth.VerificationURI+"/verify",
		strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = s.DoRequest(req)
	if err != nil {
		return fmt.Errorf("verification request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for successful verification
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		body, _ := s.ReadBody(resp)
		return fmt.Errorf("verification failed with status %d: %s",
			resp.StatusCode, body)
	}

	return nil
}
