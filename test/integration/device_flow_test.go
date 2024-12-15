// Package integration provides end-to-end testing for OAuth 2.0 Device Flow implementation.
// It verifies compliance with RFC 8628 OAuth 2.0 Device Authorization Grant.
package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestDeviceFlow is the main test suite for RFC 8628 compliance. It verifies the complete
// device authorization flow from initial request through token issuance.
func TestDeviceFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping RFC 8628 compliance test in short mode")
	}

	suite := NewSuite(t)
	t.Log("Starting OAuth 2.0 Device Authorization Grant compliance testing")

	if err := suite.WaitForServices(); err != nil {
		t.Fatalf("Failed waiting for services: %v", err)
	}

	// We structure our tests to follow the RFC sections for clarity
	t.Run("3.1-3.2 Device Authorization", func(t *testing.T) {
		testDeviceAuthorization(t, suite)
	})
}

// testDeviceAuthorization verifies compliance with RFC 8628 Sections 3.1-3.2.
// It tests both the device authorization request requirements and response format.
func testDeviceAuthorization(t *testing.T, s *TestSuite) {
	// First test error conditions for the device authorization request
	t.Run("3.1 Request Validation", func(t *testing.T) {
		// Test missing client_id
		t.Run("Missing client_id", func(t *testing.T) {
			resp, body := doDeviceAuthRequest(t, s, nil)
			assertError(t, resp, body, "invalid_request",
				"client_id is REQUIRED for public clients (Section 3.1)")
		})

		// Test duplicate parameters
		t.Run("Duplicate Parameters", func(t *testing.T) {
			// Build request with duplicate client_id
			data := url.Values{}
			data.Add("client_id", "test-client")
			data.Add("client_id", "test-client-2")

			req, err := http.NewRequestWithContext(s.Ctx, "POST",
				ProxyEndpoint+"/device/code",
				strings.NewReader(data.Encode()))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := s.DoRequest(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, err := s.ReadBody(resp)
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}

			assertError(t, resp, body, "invalid_request",
				"Parameters MUST NOT be included more than once (Section 3.1)")
		})

		// Test successful device authorization with full flow
		t.Run("3.2 Successful Flow", func(t *testing.T) {
			// Request device authorization
			resp, body := doDeviceAuthRequest(t, s, map[string]string{
				"client_id": "test-client",
				"scope":     "test-scope",
			})

			// Verify response format and headers
			if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
				t.Error("Response MUST be JSON (Section 3.2)")
			}
			if resp.Header.Get("Cache-Control") != "no-store" {
				t.Error("Response MUST include Cache-Control: no-store (Section 3.2)")
			}

			// Parse and validate the authorization response
			var auth deviceAuthResponse
			if err := json.Unmarshal(body, &auth); err != nil {
				t.Fatalf("Response not valid JSON: %v", err)
			}
			validateDeviceAuthResponse(t, &auth)

			// Test the full token flow with this authorization
			t.Run("3.3-3.5 Token Flow", func(t *testing.T) {
				testTokenFlow(t, s, &auth)
			})
		})
	})
}

// testTokenFlow verifies the token request and response flow specified in RFC 8628
// Sections 3.3-3.5. This includes polling behavior, error handling, and successful
// token issuance.
func testTokenFlow(t *testing.T, s *TestSuite, auth *deviceAuthResponse) {
	t.Run("3.4 Token Request", func(t *testing.T) {
		// Test required parameters
		t.Run("Missing grant_type", func(t *testing.T) {
			resp, body := doTokenRequest(t, s, map[string]string{
				"device_code": auth.DeviceCode,
				"client_id":   "test-client",
			})
			assertError(t, resp, body, "invalid_request",
				"grant_type is REQUIRED (Section 3.4)")
		})

		t.Run("Missing device_code", func(t *testing.T) {
			resp, body := doTokenRequest(t, s, map[string]string{
				"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":  "test-client",
			})
			assertError(t, resp, body, "invalid_request",
				"device_code is REQUIRED (Section 3.4)")
		})

		t.Run("Invalid grant_type", func(t *testing.T) {
			resp, body := doTokenRequest(t, s, map[string]string{
				"grant_type":  "invalid_grant_type",
				"device_code": auth.DeviceCode,
				"client_id":   "test-client",
			})
			assertError(t, resp, body, "unsupported_grant_type",
				"grant_type must be urn:ietf:params:oauth:grant-type:device_code")
		})
	})

	// Test error handling from Section 3.5
	t.Run("3.5 Error Responses", func(t *testing.T) {
		// Test authorization_pending
		t.Run("authorization_pending", func(t *testing.T) {
			resp, body := doTokenRequest(t, s, map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": auth.DeviceCode,
				"client_id":   "test-client",
			})
			assertError(t, resp, body, "authorization_pending",
				"Should return authorization_pending before user approval")
		})

		// Test slow_down with rate limiting
		t.Run("slow_down", func(t *testing.T) {
			start := time.Now()
			sawSlowDown := false
			initInterval := DefaultPollingInterval

			for i := 0; i < 20 && !sawSlowDown && time.Since(start) < 10*time.Second; i++ {
				resp, body := doTokenRequest(t, s, map[string]string{
					"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
					"device_code": auth.DeviceCode,
					"client_id":   "test-client",
				})

				if resp.StatusCode != http.StatusOK {
					var errResp errorResponse
					if err := json.Unmarshal(body, &errResp); err == nil &&
						errResp.Error == "slow_down" {
						sawSlowDown = true

						// Verify increased interval is respected
						time.Sleep(initInterval + 5*time.Second)
						nextResp, nextBody := doTokenRequest(t, s, map[string]string{
							"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
							"device_code": auth.DeviceCode,
							"client_id":   "test-client",
						})

						var nextErr errorResponse
						if err := json.Unmarshal(nextBody, &nextErr); err == nil &&
							nextErr.Error == "slow_down" {
							t.Error("Got slow_down even after respecting increased interval")
						}
						break
					}
				}
				time.Sleep(100 * time.Millisecond)
			}

			if !sawSlowDown {
				t.Error("Rate limiting did not trigger slow_down error")
			}
		})

		// Test successful flow after user approval
		t.Run("Successful Token Issuance", func(t *testing.T) {
			// Simulate user approving the device
			if err := simulateUserVerification(s, auth); err != nil {
				t.Fatalf("User verification failed: %v", err)
			}

			// Poll for token with proper interval
			token, err := pollForToken(s.Ctx, t, s, auth)
			if err != nil {
				t.Fatalf("Token polling failed: %v", err)
			}

			validateTokenResponse(t, token)
		})

		// Test expired_token after expiry
		t.Run("expired_token", func(t *testing.T) {
			// Wait for expiration
			if auth.ExpiresIn > 0 {
				time.Sleep(time.Duration(auth.ExpiresIn+1) * time.Second)
			}

			resp, body := doTokenRequest(t, s, map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": auth.DeviceCode,
				"client_id":   "test-client",
			})
			assertError(t, resp, body, "expired_token",
				"Device code should expire after expires_in seconds")
		})
	})
}
