// Package integration provides end-to-end testing for OAuth 2.0 Device Flow implementation
package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Response types matching RFC 8628
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func TestDeviceFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	suite := NewSuite(t)
	t.Log("Starting device flow test with OAuth 2.0 Device Authorization Grant (RFC 8628)")

	// Wait for all services to be ready
	if err := suite.WaitForServices(); err != nil {
		t.Fatalf("Failed waiting for services: %v", err)
	}

	// Step 1: Request Device Code
	t.Run("device authorization request", func(t *testing.T) {
		deviceAuth, err := requestDeviceCode(suite)
		if err != nil {
			t.Fatalf("Device authorization request failed: %v", err)
		}

		t.Logf("Received device authorization response: %+v", deviceAuth)
		validateDeviceAuthResponse(t, deviceAuth)

		// Step 2: Simulate User Verification
		t.Run("user verification", func(t *testing.T) {
			if err := simulateUserVerification(suite, deviceAuth); err != nil {
				t.Fatalf("User verification failed: %v", err)
			}
		})

		// Step 3: Poll for Token
		t.Run("token polling", func(t *testing.T) {
			token, err := pollForToken(suite, deviceAuth)
			if err != nil {
				t.Fatalf("Token polling failed: %v", err)
			}
			validateTokenResponse(t, token)
		})

		// Step 4: Test Rate Limiting
		t.Run("rate limiting", func(t *testing.T) {
			testRateLimiting(t, suite, deviceAuth)
		})
	})
}

func requestDeviceCode(s *TestSuite) (*deviceAuthResponse, error) {
	s.T.Log("Requesting device code...")
	data := url.Values{
		"client_id": {"test-client"},
		"scope":     {"test-scope"},
	}

	req, err := http.NewRequestWithContext(s.Ctx, "POST",
		ProxyEndpoint+"/device/code",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.DoRequest(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := s.ReadBody(resp)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to decode error response
		var errResp errorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			return nil, fmt.Errorf("error response: %s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var response deviceAuthResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &response, nil
}

func validateDeviceAuthResponse(t *testing.T, resp *deviceAuthResponse) {
	t.Helper()

	var issues []string
	if resp.DeviceCode == "" {
		issues = append(issues, "device_code is required")
	}
	if resp.UserCode == "" {
		issues = append(issues, "user_code is required")
	}
	if resp.VerificationURI == "" {
		issues = append(issues, "verification_uri is required")
	}
	if resp.ExpiresIn <= 0 {
		issues = append(issues, fmt.Sprintf("expires_in must be positive, got %d", resp.ExpiresIn))
	}
	if resp.Interval <= 0 {
		issues = append(issues, fmt.Sprintf("interval must be positive, got %d", resp.Interval))
	}
	if resp.VerificationURIComplete == "" {
		t.Log("verification_uri_complete not provided (optional per RFC 8628)")
	}

	if len(issues) > 0 {
		t.Errorf("Invalid device authorization response:\n%s", strings.Join(issues, "\n"))
	}
}

func simulateUserVerification(s *TestSuite, auth *deviceAuthResponse) error {
	s.T.Log("Simulating user verification...")

	// First try GET to fetch verification form
	s.T.Log("Fetching verification form...")
	req, err := http.NewRequestWithContext(s.Ctx, "GET", auth.VerificationURI, nil)
	if err != nil {
		return fmt.Errorf("creating GET request: %w", err)
	}

	resp, err := s.DoRequest(req)
	if err != nil {
		return fmt.Errorf("getting verification page: %w", err)
	}

	body, err := s.ReadBody(resp)
	if err != nil {
		return fmt.Errorf("reading verification page: %w", err)
	}
	resp.Body.Close()

	// Extract CSRF token
	csrfToken := s.ExtractCSRFToken(string(body))
	if csrfToken == "" {
		return fmt.Errorf("CSRF token not found")
	}

	// Submit verification form
	s.T.Log("Submitting verification form...")
	data := url.Values{
		"code":       {auth.UserCode},
		"csrf_token": {csrfToken},
	}

	req, err = http.NewRequestWithContext(s.Ctx, "POST", auth.VerificationURI,
		strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("creating POST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = s.DoRequest(req)
	if err != nil {
		return fmt.Errorf("submitting verification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusMethodNotAllowed {
		// Try with /verify endpoint if base path doesn't accept POST
		verifyURL := auth.VerificationURI + "/verify"
		s.T.Logf("Got 405, retrying with %s...", verifyURL)

		req, err = http.NewRequestWithContext(s.Ctx, "POST", verifyURL,
			strings.NewReader(data.Encode()))
		if err != nil {
			return fmt.Errorf("creating verify POST request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err = s.DoRequest(req)
		if err != nil {
			return fmt.Errorf("submitting to verify endpoint: %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		body, _ := s.ReadBody(resp)
		return fmt.Errorf("verification failed with status %d: %s", resp.StatusCode, body)
	}

	return nil
}

func pollForToken(s *TestSuite, auth *deviceAuthResponse) (*tokenResponse, error) {
	s.T.Log("Starting token polling...")
	ticker := time.NewTicker(time.Duration(auth.Interval) * time.Second)
	defer ticker.Stop()

	attempt := 0
	maxAttempts := 30 // Prevent infinite polling in tests

	for {
		attempt++
		if attempt > maxAttempts {
			return nil, fmt.Errorf("exceeded maximum polling attempts")
		}

		select {
		case <-s.Ctx.Done():
			return nil, s.Ctx.Err()
		case <-ticker.C:
			s.T.Logf("Polling attempt %d/%d...", attempt, maxAttempts)
			token, err := tryTokenRequest(s, auth.DeviceCode)
			if err != nil {
				// Try to parse error response
				var errStr string
				var errResp errorResponse
				if jsonErr := json.Unmarshal([]byte(err.Error()), &errResp); jsonErr == nil {
					errStr = errResp.Error
				} else {
					errStr = err.Error()
				}

				switch errStr {
				case "authorization_pending":
					s.T.Log("Authorization pending, continuing to poll...")
					continue
				case "slow_down":
					s.T.Log("Received slow_down, increasing interval...")
					newInterval := time.Duration(auth.Interval+5) * time.Second
					ticker.Reset(newInterval)
					continue
				default:
					return nil, fmt.Errorf("token request failed: %v", err)
				}
			}
			s.T.Log("Successfully retrieved token")
			return token, nil
		}
	}
}

func tryTokenRequest(s *TestSuite, deviceCode string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"test-client"},
	}

	req, err := http.NewRequestWithContext(s.Ctx, "POST",
		ProxyEndpoint+"/device/token",
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.DoRequest(req)
	if err != nil {
		return nil, fmt.Errorf("sending token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := s.ReadBody(resp)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to decode error response
		var errResp errorResponse
		if err := json.Unmarshal(body, &errResp); err == nil {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.ErrorDescription)
		}
		return nil, fmt.Errorf("unexpected response: %q", string(body))
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	return &token, nil
}

func validateTokenResponse(t *testing.T, token *tokenResponse) {
	t.Helper()

	var issues []string
	if token.AccessToken == "" {
		issues = append(issues, "access_token is required")
	}
	if token.TokenType == "" {
		issues = append(issues, "token_type is required")
	}
	if token.ExpiresIn <= 0 {
		issues = append(issues, fmt.Sprintf("expires_in must be positive, got %d", token.ExpiresIn))
	}

	if len(issues) > 0 {
		t.Errorf("Invalid token response:\n%s", strings.Join(issues, "\n"))
	}
}

func testRateLimiting(t *testing.T, s *TestSuite, auth *deviceAuthResponse) {
	t.Helper()

	t.Log("Testing rate limiting...")
	sawSlowDown := false

	// Make rapid requests to trigger rate limiting
	for i := 0; i < 20 && !sawSlowDown; i++ {
		time.Sleep(100 * time.Millisecond) // Small delay to not overwhelm
		t.Logf("Rate limit test request %d/20", i+1)

		data := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {auth.DeviceCode},
			"client_id":   {"test-client"},
		}

		req, err := http.NewRequestWithContext(s.Ctx, "POST",
			ProxyEndpoint+"/device/token",
			strings.NewReader(data.Encode()))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := s.DoRequest(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode == http.StatusBadRequest {
			var errResp errorResponse
			body, err := s.ReadBody(resp)
			if err != nil {
				resp.Body.Close()
				t.Fatalf("Failed to read error response: %v", err)
			}
			resp.Body.Close()

			if err := json.Unmarshal(body, &errResp); err != nil {
				t.Fatalf("Failed to decode error response: %v", err)
			}

			if errResp.Error == "slow_down" {
				t.Log("Received expected slow_down error")
				sawSlowDown = true
				break
			}
		} else {
			resp.Body.Close()
		}
	}

	if !sawSlowDown {
		t.Error("Rate limiting did not trigger slow_down error")
	}
}
