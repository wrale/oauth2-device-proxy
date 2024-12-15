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
	ExpiresIn              int    `json:"expires_in"`
	Interval               int    `json:"interval"`
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

		// Validate response per RFC 8628 section 3.2
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
	data := url.Values{
		"client_id": {"test-client"},
		"scope":     {"test-scope"},
	}

	resp, err := s.Client.Post(
		ProxyEndpoint+"/device/code",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var response deviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &response, nil
}

func validateDeviceAuthResponse(t *testing.T, resp *deviceAuthResponse) {
	t.Helper()

	if resp.DeviceCode == "" {
		t.Error("device_code is required")
	}
	if resp.UserCode == "" {
		t.Error("user_code is required")
	}
	if resp.VerificationURI == "" {
		t.Error("verification_uri is required")
	}
	if resp.ExpiresIn <= 0 {
		t.Error("expires_in must be positive")
	}
	if resp.Interval <= 0 {
		t.Error("interval must be positive")
	}
	if resp.VerificationURIComplete == "" {
		t.Log("verification_uri_complete not provided (optional per RFC 8628)")
	}
}

func simulateUserVerification(s *TestSuite, auth *deviceAuthResponse) error {
	// Get verification page to obtain CSRF token
	resp, err := s.Client.Get(auth.VerificationURI)
	if err != nil {
		return fmt.Errorf("getting verification page: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("reading verification page: %w", err)
	}

	// Extract CSRF token
	csrfToken := s.ExtractCSRFToken(string(body))
	if csrfToken == "" {
		return fmt.Errorf("CSRF token not found")
	}

	// Submit verification form
	data := url.Values{
		"code":       {auth.UserCode},
		"csrf_token": {csrfToken},
	}

	resp, err = s.Client.Post(
		auth.VerificationURI,
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return fmt.Errorf("submitting verification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("verification failed with status %d: %s", resp.StatusCode, body)
	}

	return nil
}

func pollForToken(s *TestSuite, auth *deviceAuthResponse) (*tokenResponse, error) {
	ticker := time.NewTicker(time.Duration(auth.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.Ctx.Done():
			return nil, s.Ctx.Err()
		case <-ticker.C:
			token, err := tryTokenRequest(s, auth.DeviceCode)
			if err != nil {
				var errResp errorResponse
				if err := json.Unmarshal([]byte(err.Error()), &errResp); err != nil {
					return nil, fmt.Errorf("invalid error response: %w", err)
				}

				switch errResp.Error {
				case "authorization_pending":
					continue // Keep polling
				case "slow_down":
					// Increase interval per RFC 8628
					newInterval := time.Duration(auth.Interval+5) * time.Second
					ticker.Reset(newInterval)
					continue
				default:
					return nil, fmt.Errorf("token request failed: %s", errResp.Error)
				}
			}
			return token, nil
		}
	}
}

func tryTokenRequest(s *TestSuite, deviceCode string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":   {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":  {deviceCode},
		"client_id":    {"test-client"},
	}

	resp, err := s.Client.Post(
		ProxyEndpoint+"/device/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(string(body))
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}

	return &token, nil
}

func validateTokenResponse(t *testing.T, token *tokenResponse) {
	t.Helper()

	if token.AccessToken == "" {
		t.Error("access_token is required")
	}
	if token.TokenType == "" {
		t.Error("token_type is required")
	}
	if token.ExpiresIn <= 0 {
		t.Error("expires_in must be positive")
	}
}

func testRateLimiting(t *testing.T, s *TestSuite, auth *deviceAuthResponse) {
	t.Helper()

	// Make rapid requests to trigger rate limiting
	sawSlowDown := false
	for i := 0; i < 20 && !sawSlowDown; i++ {
		time.Sleep(100 * time.Millisecond) // Small delay to not overwhelm
		
		data := url.Values{
			"grant_type":   {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code":  {auth.DeviceCode},
			"client_id":    {"test-client"},
		}

		resp, err := s.Client.Post(
			ProxyEndpoint+"/device/token",
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}

		if resp.StatusCode == http.StatusBadRequest {
			var errResp errorResponse
			if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
				resp.Body.Close()
				t.Fatalf("Failed to decode error response: %v", err)
			}
			resp.Body.Close()

			if errResp.Error == "slow_down" {
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
