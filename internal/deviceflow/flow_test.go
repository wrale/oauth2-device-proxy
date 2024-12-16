// Package deviceflow implements OAuth 2.0 Device Authorization Grant per RFC 8628
package deviceflow

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRequestDeviceCode tests the primary RFC 8628 section 3.1-3.3 endpoint
func TestRequestDeviceCode(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		userCode string
		wantBase string
		wantFull string
	}{
		{
			name:     "valid code with trailing slash",
			baseURL:  "https://example.com/",
			userCode: "WDJB-MJHT", // Valid code from RFC 8628 section 6.1
			wantBase: "https://example.com/device",
			wantFull: "https://example.com/device?code=WDJB-MJHT",
		},
		{
			name:     "valid code without trailing slash",
			baseURL:  "https://example.com",
			userCode: "WDJB-MJHT",
			wantBase: "https://example.com/device",
			wantFull: "https://example.com/device?code=WDJB-MJHT",
		},
		{
			name:     "baseURL with path",
			baseURL:  "https://example.com/auth/flow",
			userCode: "WDJB-MJHT",
			wantBase: "https://example.com/auth/flow/device",
			wantFull: "https://example.com/auth/flow/device?code=WDJB-MJHT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock store that returns predefined user code
			mockStore := &mockStore{
				saveDeviceCode: func(ctx context.Context, code *DeviceCode) error {
					return nil // Always succeed for this test
				},
				generateUserCode: func() (string, error) {
					return tt.userCode, nil
				},
			}

			// Create flow with test baseURL
			flow := NewFlow(mockStore, tt.baseURL)

			// Get device code response per RFC 8628 section 3.2
			code, err := flow.RequestDeviceCode(context.Background(), "test-client", "test-scope")
			if err != nil {
				t.Fatalf("RequestDeviceCode failed: %v", err)
			}

			// Verify required fields from RFC 8628 section 3.2
			if code.VerificationURI != tt.wantBase {
				t.Errorf("base URI: got %q, want %q", code.VerificationURI, tt.wantBase)
			}

			if code.VerificationURIComplete != tt.wantFull {
				t.Errorf("complete URI: got %q, want %q", code.VerificationURIComplete, tt.wantFull)
			}

			if code.UserCode != tt.userCode {
				t.Errorf("user code: got %q, want %q", code.UserCode, tt.userCode)
			}

			if code.DeviceCode == "" {
				t.Error("device code should not be empty")
			}

			if code.ExpiresIn < int(MinExpiryDuration.Seconds()) {
				t.Errorf("expiry %d should be >= %d seconds", code.ExpiresIn, int(MinExpiryDuration.Seconds()))
			}

			if code.Interval < int(MinPollInterval.Seconds()) {
				t.Errorf("interval %d should be >= %d seconds", code.Interval, int(MinPollInterval.Seconds()))
			}

			// Test response for proper URI formatting
			if code.VerificationURIComplete != "" {
				// Complete URI should start with base URI
				if !strings.HasPrefix(code.VerificationURIComplete, code.VerificationURI) {
					t.Error("complete URI should start with base URI")
				}

				// URI encoding should be correct - no spaces
				if strings.Contains(code.VerificationURIComplete, " ") {
					t.Error("complete URI contains unencoded spaces")
				}

				// Code should be preserved exactly per RFC 8628 section 6.1
				if !strings.Contains(code.VerificationURIComplete, tt.userCode) {
					t.Error("complete URI should contain unmodified user code")
				}
			}
		})
	}
}
