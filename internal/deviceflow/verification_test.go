// Package deviceflow implements verification tests
package deviceflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// TestVerifyUserCode tests the user code verification per RFC 8628 sections 3.3 and 5.2
func TestVerifyUserCode(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T, *mockStore)
		userCode string
		wantErr  error
	}{
		{
			name: "valid code",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "ABCD-EFGH",
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("failed to setup test: %v", err)
				}
			},
			userCode: "ABCD-EFGH",
			wantErr:  nil,
		},
		{
			name:     "invalid code",
			setup:    func(t *testing.T, s *mockStore) {},
			userCode: "XXXX-YYYY",
			wantErr:  ErrInvalidUserCode,
		},
		{
			name: "expired code",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "ABCD-EFGH",
					ExpiresAt:  time.Now().Add(-1 * time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("failed to setup test: %v", err)
				}
			},
			userCode: "ABCD-EFGH",
			wantErr:  ErrExpiredCode,
		},
		{
			name: "rate limit exceeded",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "ABCD-EFGH",
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
			userCode: "ABCD-EFGH",
			wantErr:  ErrRateLimitExceeded,
		},
		{
			name: "store error",
			setup: func(t *testing.T, s *mockStore) {
				s.healthy = false
			},
			userCode: "ABCD-EFGH",
			wantErr:  ErrStoreUnhealthy,
		},
		{
			name: "normalize case and spaces",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test-device",
					UserCode:   "ABCD-EFGH",
					ExpiresAt:  time.Now().Add(10 * time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("failed to setup test: %v", err)
				}
			},
			userCode: " abcd-efgh ", // Should be normalized
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
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if code == nil {
					t.Fatal("expected non-nil DeviceCode")
				}

				// Additional checks for valid codes per RFC 8628
				if tt.userCode != code.UserCode {
					normalized := validation.NormalizeCode(tt.userCode)
					storedNormalized := validation.NormalizeCode(code.UserCode)
					if normalized != storedNormalized {
						t.Errorf("codes don't match after normalization: %q != %q",
							normalized, storedNormalized)
					}
				}
			}
		})
	}
}
