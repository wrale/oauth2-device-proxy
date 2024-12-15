// Package deviceflow implements URI handling tests
package deviceflow

import (
	"strings"
	"testing"
)

func TestBuildVerificationURIs(t *testing.T) {
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
			userCode: "WDJB-MJHT", // Valid code from RFC 8628 character set
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
			name:     "invalid code",
			baseURL:  "https://example.com",
			userCode: "invalid", // Invalid format
			wantBase: "https://example.com/device",
			wantFull: "", // No complete URI for invalid codes
		},
		{
			name:     "code with special characters",
			baseURL:  "https://example.com",
			userCode: "WD#B-MJ&T", // Invalid chars
			wantBase: "https://example.com/device",
			wantFull: "", // Invalid code - no complete URI
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
			flow := NewFlow(newMockStore(), tt.baseURL)
			base, full := flow.buildVerificationURIs(tt.userCode)

			if base != tt.wantBase {
				t.Errorf("base URI: got %q, want %q", base, tt.wantBase)
			}

			if full != tt.wantFull {
				t.Errorf("complete URI: got %q, want %q", full, tt.wantFull)
			}

			if full != "" {
				// Verify complete URI structure
				if !strings.HasPrefix(full, base) {
					t.Error("complete URI should start with base URI")
				}

				// URI encoding should be correct
				if strings.Contains(full, " ") {
					t.Error("complete URI contains unencoded spaces")
				}

				// Code should be preserved exactly
				if !strings.Contains(full, tt.userCode) {
					t.Error("complete URI should contain unmodified user code")
				}
			}
		})
	}
}
