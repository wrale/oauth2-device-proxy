// Package deviceflow implements test helpers for device flow tests
package deviceflow

import (
	"context"
	"errors"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// ErrStoreUnhealthy indicates the store is not available
var ErrStoreUnhealthy = errors.New("store unhealthy")

// mockStore implements Store interface for testing
type mockStore struct {
	deviceCodes map[string]*DeviceCode
	userCodes   map[string]string // user code -> device code
	tokens      map[string]*TokenResponse
	attempts    map[string]int // device code -> attempt count
	healthy     bool
}

func newMockStore() *mockStore {
	return &mockStore{
		deviceCodes: make(map[string]*DeviceCode),
		userCodes:   make(map[string]string),
		tokens:      make(map[string]*TokenResponse),
		attempts:    make(map[string]int),
		healthy:     true,
	}
}

func (m *mockStore) SaveDeviceCode(ctx context.Context, code *DeviceCode) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	m.deviceCodes[code.DeviceCode] = code
	m.userCodes[validation.NormalizeCode(code.UserCode)] = code.DeviceCode
	return nil
}

func (m *mockStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	if !m.healthy {
		return nil, ErrStoreUnhealthy
	}
	code, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil, nil
	}
	return code, nil
}

func (m *mockStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	if !m.healthy {
		return nil, ErrStoreUnhealthy
	}
	deviceCode, exists := m.userCodes[validation.NormalizeCode(userCode)]
	if !exists {
		return nil, nil
	}
	return m.GetDeviceCode(ctx, deviceCode)
}

func (m *mockStore) SaveToken(ctx context.Context, deviceCode string, token *TokenResponse) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	m.tokens[deviceCode] = token
	return nil
}

func (m *mockStore) GetToken(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	if !m.healthy {
		return nil, ErrStoreUnhealthy
	}
	token, exists := m.tokens[deviceCode]
	if !exists {
		return nil, nil
	}
	return token, nil
}

func (m *mockStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	code, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil
	}
	delete(m.deviceCodes, deviceCode)
	delete(m.userCodes, validation.NormalizeCode(code.UserCode))
	delete(m.tokens, deviceCode)
	delete(m.attempts, deviceCode)
	return nil
}

func (m *mockStore) CheckHealth(ctx context.Context) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	return nil
}

func (m *mockStore) CheckDeviceCodeAttempts(ctx context.Context, deviceCode string) (bool, error) {
	if !m.healthy {
		return false, ErrStoreUnhealthy
	}

	// Track verification attempts for this code
	m.attempts[deviceCode]++

	// RFC 8628 section 5.2 recommends limiting verification attempts
	maxAttempts := 50
	return m.attempts[deviceCode] <= maxAttempts, nil
}
