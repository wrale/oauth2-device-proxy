// Package deviceflow implements test helpers for device flow tests
package deviceflow

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// ErrStoreUnhealthy indicates the store is not available
var ErrStoreUnhealthy = errors.New("store unhealthy")

// mockStore implements Store interface for testing
type mockStore struct {
	mu           sync.Mutex // Protect concurrent map access
	deviceCodes  map[string]*DeviceCode
	userCodes    map[string]string // user code -> device code
	tokens       map[string]*TokenResponse
	polls        map[string][]time.Time // device code -> poll timestamps
	attempts     map[string]int         // device code -> verification attempts
	healthy      bool
	mockUserCode string // For testing specific user code scenarios
}

func newMockStore() *mockStore {
	return &mockStore{
		deviceCodes: make(map[string]*DeviceCode),
		userCodes:   make(map[string]string),
		tokens:      make(map[string]*TokenResponse),
		polls:       make(map[string][]time.Time),
		attempts:    make(map[string]int),
		healthy:     true,
	}
}

func (m *mockStore) SaveDeviceCode(ctx context.Context, code *DeviceCode) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deviceCodes[code.DeviceCode] = code
	m.userCodes[validation.NormalizeCode(code.UserCode)] = code.DeviceCode
	return nil
}

func (m *mockStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	if !m.healthy {
		return nil, ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return fixed user code if set for testing
	if m.mockUserCode != "" {
		return &DeviceCode{UserCode: m.mockUserCode}, nil
	}

	deviceCode, exists := m.userCodes[validation.NormalizeCode(userCode)]
	if !exists {
		return nil, nil
	}
	code, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil, nil
	}
	return code, nil
}

func (m *mockStore) GetTokenResponse(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	if !m.healthy {
		return nil, ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[deviceCode]
	if !exists {
		return nil, nil
	}
	return token, nil
}

func (m *mockStore) SaveTokenResponse(ctx context.Context, deviceCode string, token *TokenResponse) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[deviceCode] = token
	return nil
}

func (m *mockStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	code, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil
	}
	delete(m.deviceCodes, deviceCode)
	delete(m.userCodes, validation.NormalizeCode(code.UserCode))
	delete(m.tokens, deviceCode)
	delete(m.polls, deviceCode)
	delete(m.attempts, deviceCode) // Also clean up attempts
	return nil
}

func (m *mockStore) GetPollCount(ctx context.Context, deviceCode string, window time.Duration) (int, error) {
	if !m.healthy {
		return 0, ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	polls := m.polls[deviceCode]
	if len(polls) == 0 {
		return 0, nil
	}

	// Count polls within window
	cutoff := time.Now().Add(-window)
	count := 0
	for _, ts := range polls {
		if ts.After(cutoff) {
			count++
		}
	}
	return count, nil
}

func (m *mockStore) UpdatePollTimestamp(ctx context.Context, deviceCode string) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	code, exists := m.deviceCodes[deviceCode]
	if !exists {
		return nil
	}

	code.LastPoll = time.Now()
	return nil
}

func (m *mockStore) IncrementPollCount(ctx context.Context, deviceCode string) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.polls[deviceCode] = append(m.polls[deviceCode], time.Now())
	return nil
}

func (m *mockStore) IncrementVerificationAttempts(deviceCode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[deviceCode]++
}

func (m *mockStore) GetVerificationAttempts(deviceCode string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts[deviceCode]
}

func (m *mockStore) CheckHealth(ctx context.Context) error {
	if !m.healthy {
		return ErrStoreUnhealthy
	}
	return nil
}
