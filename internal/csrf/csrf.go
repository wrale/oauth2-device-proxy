// Package csrf provides CSRF protection for web handlers
package csrf

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidToken indicates a missing or invalid CSRF token
	ErrInvalidToken = errors.New("invalid csrf token")

	// ErrTokenExpired indicates the CSRF token has expired
	ErrTokenExpired = errors.New("csrf token expired")
)

// Store provides token storage operations
type Store interface {
	// SaveToken stores a CSRF token with expiry
	SaveToken(ctx context.Context, token string, expiresIn time.Duration) error

	// ValidateToken checks if a token exists and is valid
	ValidateToken(ctx context.Context, token string) error

	// CheckHealth verifies the store is operational
	CheckHealth(ctx context.Context) error
}

// Manager handles CSRF token generation and validation
type Manager struct {
	store     Store
	secret    []byte
	expiresIn time.Duration
}

// NewManager creates a new CSRF token manager
func NewManager(store Store, secret []byte, expiresIn time.Duration) *Manager {
	return &Manager{
		store:     store,
		secret:    secret,
		expiresIn: expiresIn,
	}
}

// GenerateToken creates and stores a new CSRF token
func (m *Manager) GenerateToken(ctx context.Context) (string, error) {
	// Generate 32 bytes of random data
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	// Create base64-encoded token
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Create HMAC signature
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(token))
	sig := h.Sum(nil)

	// Combine token and signature
	fullToken := fmt.Sprintf("%s.%s",
		token,
		base64.URLEncoding.EncodeToString(sig),
	)

	// Store token
	if err := m.store.SaveToken(ctx, fullToken, m.expiresIn); err != nil {
		return "", fmt.Errorf("saving token: %w", err)
	}

	return fullToken, nil
}

// ValidateToken checks if a token is valid
func (m *Manager) ValidateToken(ctx context.Context, token string) error {
	// Validate token format
	if token == "" {
		return ErrInvalidToken
	}

	// Split token and signature
	parts := split(token, ".", 2)
	if len(parts) != 2 {
		return ErrInvalidToken
	}

	// Verify HMAC signature
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(parts[0])) // token
	expectedSig := h.Sum(nil)

	actualSig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrInvalidToken
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return ErrInvalidToken
	}

	// Check token validity in store
	if err := m.store.ValidateToken(ctx, token); err != nil {
		return fmt.Errorf("validating token: %w", err)
	}

	return nil
}

// CheckHealth verifies the CSRF manager is operational
func (m *Manager) CheckHealth(ctx context.Context) error {
	if err := m.store.CheckHealth(ctx); err != nil {
		return fmt.Errorf("csrf store health check failed: %w", err)
	}
	return nil
}

// Helper to safely split string
func split(s, sep string, n int) []string {
	parts := make([]string, n)
	if s == "" {
		return parts
	}

	// Split only up to n parts
	remaining := s
	for i := 0; i < n-1; i++ {
		if idx := find(remaining, sep); idx >= 0 {
			parts[i] = remaining[:idx]
			remaining = remaining[idx+len(sep):]
		} else {
			return parts
		}
	}
	// Add remaining part
	parts[n-1] = remaining
	return parts
}

// Helper to safely find substring
func find(s, substr string) int {
	if s == "" || substr == "" {
		return -1
	}
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
