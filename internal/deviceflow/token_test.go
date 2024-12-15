// Package deviceflow implements token handling tests
package deviceflow

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCheckDeviceCode(t *testing.T) {
	tests := []struct {
		name       string
		deviceCode string
		setup      func(*testing.T, *mockStore)
		wantToken  bool
		wantErr    error
	}{
		{
			name:       "invalid device code",
			deviceCode: "invalid",
			setup:      func(t *testing.T, s *mockStore) {},
			wantToken:  false,
			wantErr:    ErrInvalidDeviceCode,
		},
		{
			name:       "expired code",
			deviceCode: "expired",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "expired",
					ExpiresAt:  time.Now().Add(-time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			},
			wantToken: false,
			wantErr:   ErrExpiredCode,
		},
		{
			name:       "rate limited",
			deviceCode: "limited",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "limited",
					ExpiresAt:  time.Now().Add(time.Hour),
					LastPoll:   time.Now(), // Just polled
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			},
			wantToken: false,
			wantErr:   ErrSlowDown,
		},
		{
			name:       "pending authorization",
			deviceCode: "pending",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "pending",
					ExpiresAt:  time.Now().Add(time.Hour),
					LastPoll:   time.Now().Add(-10 * time.Second),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			},
			wantToken: false,
			wantErr:   ErrPendingAuthorization,
		},
		{
			name:       "authorized with token",
			deviceCode: "authorized",
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "authorized",
					ExpiresAt:  time.Now().Add(time.Hour),
					LastPoll:   time.Now().Add(-10 * time.Second),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
				token := &TokenResponse{
					AccessToken: "test-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}
				if err := s.SaveToken(context.Background(), "authorized", token); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			},
			wantToken: true,
			wantErr:   nil,
		},
		{
			name:       "store error",
			deviceCode: "error",
			setup: func(t *testing.T, s *mockStore) {
				s.healthy = false
			},
			wantToken: false,
			wantErr:   ErrStoreUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setup != nil {
				tt.setup(t, store)
			}

			flow := NewFlow(store, "https://example.com")
			token, err := flow.CheckDeviceCode(context.Background(), tt.deviceCode)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantToken {
				if token == nil {
					t.Fatal("expected token, got nil")
				}
				if token.AccessToken == "" {
					t.Error("expected non-empty access token")
				}
			} else {
				if token != nil {
					t.Error("expected nil token")
				}
			}
		})
	}
}

func TestCompleteAuthorization(t *testing.T) {
	tests := []struct {
		name       string
		deviceCode string
		token      *TokenResponse
		setup      func(*testing.T, *mockStore)
		wantErr    error
	}{
		{
			name:       "success",
			deviceCode: "test",
			token: &TokenResponse{
				AccessToken: "test-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			},
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "test",
					ExpiresAt:  time.Now().Add(time.Hour),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			},
			wantErr: nil,
		},
		{
			name:       "invalid device code",
			deviceCode: "invalid",
			token: &TokenResponse{
				AccessToken: "test-token",
			},
			setup:   func(t *testing.T, s *mockStore) {},
			wantErr: ErrInvalidDeviceCode,
		},
		{
			name:       "expired code",
			deviceCode: "expired",
			token: &TokenResponse{
				AccessToken: "test-token",
			},
			setup: func(t *testing.T, s *mockStore) {
				code := &DeviceCode{
					DeviceCode: "expired",
					ExpiresAt:  time.Now().Add(-time.Minute),
				}
				if err := s.SaveDeviceCode(context.Background(), code); err != nil {
					t.Fatalf("setup failed: %v", err)
				}
			},
			wantErr: ErrExpiredCode,
		},
		{
			name:       "store error",
			deviceCode: "error",
			token: &TokenResponse{
				AccessToken: "test-token",
			},
			setup: func(t *testing.T, s *mockStore) {
				s.healthy = false
			},
			wantErr: ErrStoreUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			if tt.setup != nil {
				tt.setup(t, store)
			}

			flow := NewFlow(store, "https://example.com")
			err := flow.CompleteAuthorization(context.Background(), tt.deviceCode, tt.token)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify token was saved
			stored, err := store.GetToken(context.Background(), tt.deviceCode)
			if err != nil {
				t.Fatalf("error getting stored token: %v", err)
			}
			if stored == nil {
				t.Fatal("expected stored token, got nil")
			}
			if stored.AccessToken != tt.token.AccessToken {
				t.Errorf("expected access token %q, got %q", tt.token.AccessToken, stored.AccessToken)
			}
		})
	}
}
