package deviceflow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// mockStore implements Store interface for testing
type mockStore struct {
	deviceCodes map[string]*DeviceCode
	userCodes   map[string]string // user code -> device code
	tokens      map[string]*TokenResponse
	healthy     bool
}

func newMockStore() *mockStore {
	return &mockStore{
		deviceCodes: make(map[string]*DeviceCode),
		userCodes:   make(map[string]string),
		tokens:      make(map[string]*TokenResponse),
		healthy:     true,
	}
}

func (m *mockStore) SaveDeviceCode(ctx context.Context, code *DeviceCode) error {
	if !m.healthy {
		return errors.New("store unhealthy")
	}
	m.deviceCodes[code.DeviceCode] = code
	m.userCodes[normalizeCode(code.UserCode)] = code.DeviceCode
	return nil
}

func (m *mockStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	if !m.healthy {
		return nil, errors.New("store unhealthy")
	}
	code, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil, nil
	}
	return code, nil
}

func (m *mockStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	if !m.healthy {
		return nil, errors.New("store unhealthy")
	}
	deviceCode, exists := m.userCodes[normalizeCode(userCode)]
	if !exists {
		return nil, nil
	}
	return m.GetDeviceCode(ctx, deviceCode)
}

func (m *mockStore) SaveToken(ctx context.Context, deviceCode string, token *TokenResponse) error {
	if !m.healthy {
		return errors.New("store unhealthy")
	}
	m.tokens[deviceCode] = token
	return nil
}

func (m *mockStore) GetToken(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	if !m.healthy {
		return nil, errors.New("store unhealthy")
	}
	token, exists := m.tokens[deviceCode]
	if !exists {
		return nil, nil
	}
	return token, nil
}

func (m *mockStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	if !m.healthy {
		return errors.New("store unhealthy")
	}
	code, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil
	}
	delete(m.deviceCodes, deviceCode)
	delete(m.userCodes, normalizeCode(code.UserCode))
	delete(m.tokens, deviceCode)
	return nil
}

func (m *mockStore) CheckHealth(ctx context.Context) error {
	if !m.healthy {
		return errors.New("store unhealthy")
	}
	return nil
}

func TestRequestDeviceCode(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		scope     string
		storeErr  bool
		wantErr   bool
		checkCode func(*testing.T, *DeviceCode)
	}{
		{
			name:     "success without scope",
			clientID: "test-client",
			wantErr:  false,
			checkCode: func(t *testing.T, code *DeviceCode) {
				if code.ClientID != "test-client" {
					t.Errorf("expected client ID %q, got %q", "test-client", code.ClientID)
				}
				if code.Scope != "" {
					t.Errorf("expected empty scope, got %q", code.Scope)
				}
				if !strings.Contains(code.VerificationURI, "/device") {
					t.Errorf("expected verification URI to contain /device, got %q", code.VerificationURI)
				}
				if code.Interval != 5 {
					t.Errorf("expected interval 5, got %d", code.Interval)
				}
				if time.Until(code.ExpiresAt) > 15*time.Minute {
					t.Error("expiry time should not exceed 15 minutes")
				}
			},
		},
		{
			name:     "success with scope",
			clientID: "test-client",
			scope:    "read write",
			wantErr:  false,
			checkCode: func(t *testing.T, code *DeviceCode) {
				if code.Scope != "read write" {
					t.Errorf("expected scope %q, got %q", "read write", code.Scope)
				}
			},
		},
		{
			name:     "store error",
			clientID: "test-client",
			storeErr: true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			store.healthy = !tt.storeErr

			flow := NewFlow(store, "https://example.com")
			code, err := flow.RequestDeviceCode(context.Background(), tt.clientID, tt.scope)

			if (err != nil) != tt.wantErr {
				t.Errorf("RequestDeviceCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if code == nil {
					t.Fatal("expected non-nil DeviceCode")
				}
				if tt.checkCode != nil {
					tt.checkCode(t, code)
				}

				// Verify code format
				if len(code.DeviceCode) != 64 { // 32 bytes hex encoded
					t.Errorf("unexpected device code length: got %d", len(code.DeviceCode))
				}
				if !strings.Contains(code.UserCode, "-") {
					t.Error("user code should contain hyphen separator")
				}
				if len(strings.ReplaceAll(code.UserCode, "-", "")) != 8 {
					t.Error("user code should be 8 characters without hyphen")
				}

				// Verify codes are stored
				stored, err := store.GetDeviceCode(context.Background(), code.DeviceCode)
				if err != nil {
					t.Errorf("error getting stored device code: %v", err)
				}
				if stored == nil {
					t.Error("device code not stored")
				}

				storedByUser, err := store.GetDeviceCodeByUserCode(context.Background(), code.UserCode)
				if err != nil {
					t.Errorf("error getting stored user code: %v", err)
				}
				if storedByUser == nil {
					t.Error("user code not stored")
				}
			}
		})
	}
}

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
			name: "store error",
			setup: func(t *testing.T, s *mockStore) {
				s.healthy = false
			},
			userCode: "ABCD-EFGH",
			wantErr:  errors.New("store unhealthy"),
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
				if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if code == nil {
					t.Fatal("expected non-nil DeviceCode")
				}
			}
		})
	}
}
