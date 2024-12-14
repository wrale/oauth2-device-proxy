package csrf

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// mockStore implements Store interface for testing
type mockStore struct {
	tokens map[string]time.Time
	err    error
}

func newMockStore() *mockStore {
	return &mockStore{
		tokens: make(map[string]time.Time),
	}
}

func (m *mockStore) SaveToken(ctx context.Context, token string, expiresIn time.Duration) error {
	if m.err != nil {
		return m.err
	}
	m.tokens[token] = time.Now().Add(expiresIn)
	return nil
}

func (m *mockStore) ValidateToken(ctx context.Context, token string) error {
	if m.err != nil {
		return m.err
	}
	expiry, exists := m.tokens[token]
	if !exists {
		return ErrInvalidToken
	}
	if time.Now().After(expiry) {
		return ErrTokenExpired
	}
	return nil
}

func (m *mockStore) CheckHealth(ctx context.Context) error {
	return m.err
}

func TestManager_GenerateToken(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	secret := []byte("test-secret-key-32-bytes-exactly!")
	manager := NewManager(store, secret, 15*time.Minute)

	t.Run("success", func(t *testing.T) {
		token, err := manager.GenerateToken(ctx)
		if err != nil {
			t.Fatalf("GenerateToken() error = %v", err)
		}

		// Verify token format
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			t.Errorf("GenerateToken() token has wrong format, got %s", token)
		}

		// Verify base64 encoding
		if _, err := base64.URLEncoding.DecodeString(parts[0]); err != nil {
			t.Errorf("GenerateToken() token part not base64: %v", err)
		}
		if _, err := base64.URLEncoding.DecodeString(parts[1]); err != nil {
			t.Errorf("GenerateToken() signature part not base64: %v", err)
		}
	})

	t.Run("store_error", func(t *testing.T) {
		store.err = errors.New("store error")
		_, err := manager.GenerateToken(ctx)
		if err == nil {
			t.Error("GenerateToken() expected error with bad store")
		}
		store.err = nil
	})

	t.Run("token_uniqueness", func(t *testing.T) {
		token1, _ := manager.GenerateToken(ctx)
		token2, _ := manager.GenerateToken(ctx)
		if token1 == token2 {
			t.Error("GenerateToken() tokens should be unique")
		}
	})
}

func TestManager_ValidateToken(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	secret := []byte("test-secret-key-32-bytes-exactly!")
	manager := NewManager(store, secret, 15*time.Minute)

	t.Run("valid_token", func(t *testing.T) {
		token, _ := manager.GenerateToken(ctx)
		if err := manager.ValidateToken(ctx, token); err != nil {
			t.Errorf("ValidateToken() error = %v", err)
		}
	})

	t.Run("empty_token", func(t *testing.T) {
		if err := manager.ValidateToken(ctx, ""); err != ErrInvalidToken {
			t.Errorf("ValidateToken() error = %v, want %v", err, ErrInvalidToken)
		}
	})

	t.Run("invalid_format", func(t *testing.T) {
		if err := manager.ValidateToken(ctx, "invalid"); err != ErrInvalidToken {
			t.Errorf("ValidateToken() error = %v, want %v", err, ErrInvalidToken)
		}
	})

	t.Run("invalid_signature", func(t *testing.T) {
		token, _ := manager.GenerateToken(ctx)
		parts := strings.Split(token, ".")
		modifiedToken := parts[0] + ".YWJj" // invalid signature
		if err := manager.ValidateToken(ctx, modifiedToken); err != ErrInvalidToken {
			t.Errorf("ValidateToken() error = %v, want %v", err, ErrInvalidToken)
		}
	})

	t.Run("expired_token", func(t *testing.T) {
		// Create token that expires immediately
		shortManager := NewManager(store, secret, -time.Second)
		token, _ := shortManager.GenerateToken(ctx)
		time.Sleep(time.Millisecond)
		if err := shortManager.ValidateToken(ctx, token); !errors.Is(err, ErrTokenExpired) {
			t.Errorf("ValidateToken() error = %v, want %v", err, ErrTokenExpired)
		}
	})

	t.Run("store_error", func(t *testing.T) {
		store.err = errors.New("store error")
		token, _ := manager.GenerateToken(ctx)
		store.err = nil // Reset error for token generation
		store.err = errors.New("store error")
		if err := manager.ValidateToken(ctx, token); err == nil {
			t.Error("ValidateToken() expected error with bad store")
		}
		store.err = nil
	})
}

func TestManager_CheckHealth(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	manager := NewManager(store, []byte("test-secret"), time.Minute)

	t.Run("healthy", func(t *testing.T) {
		if err := manager.CheckHealth(ctx); err != nil {
			t.Errorf("CheckHealth() error = %v", err)
		}
	})

	t.Run("unhealthy", func(t *testing.T) {
		store.err = errors.New("store error")
		if err := manager.CheckHealth(ctx); err == nil {
			t.Error("CheckHealth() expected error with bad store")
		}
		store.err = nil
	})
}

func TestSplit(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		sep      string
		n        int
		expected []string
	}{
		{
			name:     "normal_split",
			s:        "a.b.c",
			sep:      ".",
			n:        2,
			expected: []string{"a", "b.c"},
		},
		{
			name:     "empty_string",
			s:        "",
			sep:      ".",
			n:        2,
			expected: []string{"", ""},
		},
		{
			name:     "no_separator",
			s:        "abc",
			sep:      ".",
			n:        2,
			expected: []string{"", "abc"},
		},
		{
			name:     "extra_separators",
			s:        "a.b.c.d",
			sep:      ".",
			n:        2,
			expected: []string{"a", "b.c.d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := split(tt.s, tt.sep, tt.n)
			if len(got) != len(tt.expected) {
				t.Errorf("split() wrong length = %v, want %v", got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("split() = %v, want %v", got, tt.expected)
				}
			}
		})
	}
}

func TestFind(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected int
	}{
		{
			name:     "normal_find",
			s:        "hello.world",
			substr:   ".",
			expected: 5,
		},
		{
			name:     "not_found",
			s:        "hello",
			substr:   ".",
			expected: -1,
		},
		{
			name:     "empty_string",
			s:        "",
			substr:   ".",
			expected: -1,
		},
		{
			name:     "empty_substr",
			s:        "hello",
			substr:   "",
			expected: -1,
		},
		{
			name:     "multiple_matches",
			s:        "a.b.c",
			substr:   ".",
			expected: 1, // Returns first match
		},
		{
			name:     "substr_at_start",
			s:        ".abc",
			substr:   ".",
			expected: 0,
		},
		{
			name:     "substr_at_end",
			s:        "abc.",
			substr:   ".",
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := find(tt.s, tt.substr); got != tt.expected {
				t.Errorf("find() = %v, want %v", got, tt.expected)
			}
		})
	}
}
