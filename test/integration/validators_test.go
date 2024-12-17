// Package integration provides validation functions for testing RFC 8628 compliance
package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// validateDeviceAuthResponse verifies compliance with RFC 8628 Section 3.2
func validateDeviceAuthResponse(t *testing.T, resp *deviceAuthResponse) {
	t.Helper()

	var issues []string

	// Check REQUIRED fields
	if resp.DeviceCode == "" {
		issues = append(issues, "device_code is REQUIRED (Section 3.2)")
	}
	if resp.UserCode == "" {
		issues = append(issues, "user_code is REQUIRED (Section 3.2)")
	}
	if resp.VerificationURI == "" {
		issues = append(issues, "verification_uri is REQUIRED (Section 3.2)")
	}
	if resp.ExpiresIn <= 0 {
		issues = append(issues, fmt.Sprintf("expires_in MUST be positive, got %d (Section 3.2)",
			resp.ExpiresIn))
	}

	// Check verification_uri_complete if provided
	if resp.VerificationURIComplete != "" {
		if !strings.Contains(resp.VerificationURIComplete, resp.UserCode) {
			issues = append(issues,
				"verification_uri_complete MUST include the user code (Section 3.2)")
		}
	} else {
		t.Log("verification_uri_complete not provided (OPTIONAL per Section 3.2)")
	}

	// Check interval requirements
	if resp.Interval == 0 {
		t.Log("No interval provided, should use 5 second default (Section 3.2)")
	} else if resp.Interval < 5 {
		issues = append(issues, fmt.Sprintf(
			"interval MUST NOT be less than 5 seconds, got %d (Section 3.2)",
			resp.Interval))
	}

	if len(issues) > 0 {
		t.Errorf("Device Authorization Response validation failed:\n%s",
			strings.Join(issues, "\n"))
	}
}

// validateTokenResponse verifies compliance with RFC 8628 Section 3.5 and OAuth 2.0 specs
func validateTokenResponse(t *testing.T, token *tokenResponse) {
	t.Helper()

	var issues []string

	// Check REQUIRED fields
	if token.AccessToken == "" {
		issues = append(issues, "access_token is REQUIRED (Section 3.5)")
	}
	if token.TokenType == "" {
		issues = append(issues, "token_type is REQUIRED (Section 3.5)")
	} else if !strings.EqualFold(token.TokenType, "Bearer") {
		issues = append(issues,
			"token_type MUST be 'Bearer' (case-insensitive per RFC 6750)")
	}

	// Check RECOMMENDED fields
	if token.ExpiresIn <= 0 {
		t.Log("expires_in is RECOMMENDED to be included (RFC 6749 Section 5.1)")
	}

	if len(issues) > 0 {
		t.Errorf("Token Response validation failed:\n%s",
			strings.Join(issues, "\n"))
	}
}

// assertError verifies error responses comply with OAuth 2.0 error format
func assertError(t *testing.T, resp *http.Response, body []byte, expectedError, message string) {
	t.Helper()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for error response, got %d", resp.StatusCode)
	}

	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		t.Error("Error response must use application/json content type")
	}

	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("Error response not valid JSON: %v", err)
	}

	if errResp.Error != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, errResp.Error)
	}
	if message != "" && errResp.ErrorDescription == "" {
		t.Logf("Missing recommended error_description: %s", message)
	}
}
