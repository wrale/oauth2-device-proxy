// Package deviceflow implements verification tests
package deviceflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// TestVerifyUserCode tests user code verification per RFC 8628 sections 3.3 and 5.2
func TestVerifyUserCode(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T, *mockStore)
		userCode string
		wantCode string // Expected RFC 8628 error code
		wantMsg  string // Expected error description
		wantErr  error  // For backwards compatibility
	}{
		{
			name: "valid code",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "BDFG-HJKL", // Valid RFC 8628 charset
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("failed to setup test: %v", err)
				}
			},
			userCode: "BDFG-HJKL",
			wantErr:  nil,
		},
		{
			name:     "invalid code",
			setup:    func(t *testing.T, s *mockStore) {},
			userCode: "XXXX-YYYY",
			wantCode: ErrorCodeInvalidRequest,
			wantMsg:  "Invalid user code format: must use BCDFGHJKLMNPQRSTVWXZ charset",
			wantErr:  ErrInvalidUserCode,
		},
		{
			name: "expired code",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "BDFG-HJKL",
					ExpiresAt:  time.Now().Add(-1 * time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("failed to setup test: %v", err)
				}
			},
			userCode: "BDFG-HJKL",
			wantCode: ErrorCodeExpiredToken,
			wantMsg:  "Code has expired",
			wantErr:  ErrExpiredCode,
		},
		{
			name: "rate limit exceeded",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "BDFG-HJKL",
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("failed to setup test: %v", err)
				}
				// Exceed verification attempts per RFC 8628 section 5.2
				for i := 0; i < 51; i++ { // One more than allowed
					s.attempts[code.DeviceCode]++
				}
			},
			userCode: "BDFG-HJKL",
			wantCode: ErrorCodeSlowDown,
			wantMsg:  "Too many verification attempts, please wait",
			wantErr:  ErrRateLimitExceeded,
		},
		{
			name: "store error",
			setup: func(t *testing.T, s *mockStore) {
				s.healthy = false
			},
			userCode: "BDFG-HJKL",
			wantCode: ErrorCodeInvalidRequest,
			wantMsg:  "Error validating code: internal error",
			wantErr:  ErrStoreUnhealthy,
		},
		{
			name: "normalize case and spaces",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "BDFG-HJKL",
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("failed to setup test: %v", err)
				}
			},
			userCode: " bdfg-hjkl ", // Should be normalized
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setup != nil {
				tt.setup(t, store)
			}

			flow := NewFlow(store, "https://example.com")
			code, err := flow.VerifyUserCode(context.Background(), tt.userCode)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				var dfe *DeviceFlowError
				if errors.As(err, &dfe) {
					if tt.wantCode != "" && dfe.Code != tt.wantCode {
						t.Errorf("expected error code %q, got %q", tt.wantCode, dfe.Code)
					}
					if tt.wantMsg != "" && dfe.Description != tt.wantMsg {
						t.Errorf("expected error message %q, got %q", tt.wantMsg, dfe.Description)
					}
				} else {
					// Fallback for non-DeviceFlowError
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("expected error %v, got %v", tt.wantErr, err)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if code == nil {
					t.Fatal("expected non-nil DeviceCode")
				}

				// Additional checks for valid codes per RFC 8628
				normalized := validation.NormalizeCode(tt.userCode)
				storedNormalized := validation.NormalizeCode(code.UserCode)
				if normalized != storedNormalized {
					t.Errorf("codes don't match after normalization: %q != %q",
						normalized, storedNormalized)
				}
			}
		})
	}
}
