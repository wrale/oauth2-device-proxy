// Package deviceflow implements OAuth 2.0 Device Authorization Grant per RFC 8628
package deviceflow

import (
	"context"
	"strings"
	"testing"
	"time"
)

type mockStore struct {
	// Required Store interface methods
	saveDeviceCodeFn          func(ctx context.Context, code *DeviceCode) error
	getDeviceCodeFn           func(ctx context.Context, deviceCode string) (*DeviceCode, error)
	getDeviceCodeByUserCodeFn func(ctx context.Context, userCode string) (*DeviceCode, error)
	getTokenResponseFn        func(ctx context.Context, deviceCode string) (*TokenResponse, error)
	saveTokenResponseFn       func(ctx context.Context, deviceCode string, token *TokenResponse) error
	deleteDeviceCodeFn        func(ctx context.Context, deviceCode string) error
	getPollCountFn            func(ctx context.Context, deviceCode string, window time.Duration) (int, error)
	updatePollTimestampFn     func(ctx context.Context, deviceCode string) error
	incrementPollCountFn      func(ctx context.Context, deviceCode string) error
	checkHealthFn             func(ctx context.Context) error
}

func (m *mockStore) SaveDeviceCode(ctx context.Context, code *DeviceCode) error {
	if m.saveDeviceCodeFn != nil {
		return m.saveDeviceCodeFn(ctx, code)
	}
	return nil
}

func (m *mockStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	if m.getDeviceCodeFn != nil {
		return m.getDeviceCodeFn(ctx, deviceCode)
	}
	return nil, nil
}

func (m *mockStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	if m.getDeviceCodeByUserCodeFn != nil {
		return m.getDeviceCodeByUserCodeFn(ctx, userCode)
	}
	return nil, nil
}

func (m *mockStore) GetTokenResponse(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	if m.getTokenResponseFn != nil {
		return m.getTokenResponseFn(ctx, deviceCode)
	}
	return nil, nil
}

func (m *mockStore) SaveTokenResponse(ctx context.Context, deviceCode string, token *TokenResponse) error {
	if m.saveTokenResponseFn != nil {
		return m.saveTokenResponseFn(ctx, deviceCode, token)
	}
	return nil
}

func (m *mockStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	if m.deleteDeviceCodeFn != nil {
		return m.deleteDeviceCodeFn(ctx, deviceCode)
	}
	return nil
}

func (m *mockStore) GetPollCount(ctx context.Context, deviceCode string, window time.Duration) (int, error) {
	if m.getPollCountFn != nil {
		return m.getPollCountFn(ctx, deviceCode, window)
	}
	return 0, nil
}

func (m *mockStore) UpdatePollTimestamp(ctx context.Context, deviceCode string) error {
	if m.updatePollTimestampFn != nil {
		return m.updatePollTimestampFn(ctx, deviceCode)
	}
	return nil
}

func (m *mockStore) IncrementPollCount(ctx context.Context, deviceCode string) error {
	if m.incrementPollCountFn != nil {
		return m.incrementPollCountFn(ctx, deviceCode)
	}
	return nil
}

func (m *mockStore) CheckHealth(ctx context.Context) error {
	if m.checkHealthFn != nil {
		return m.checkHealthFn(ctx)
	}
	return nil
}

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
				saveDeviceCodeFn: func(ctx context.Context, code *DeviceCode) error {
					return nil // Always succeed for this test
				},
				getDeviceCodeByUserCodeFn: func(ctx context.Context, code string) (*DeviceCode, error) {
					if code == tt.userCode {
						return &DeviceCode{UserCode: tt.userCode}, nil
					}
					return nil, nil
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
