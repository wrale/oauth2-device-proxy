package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SaveToken stores an access token for a device code
func (s *RedisStore) SaveToken(ctx context.Context, deviceCode string, token *TokenResponse) error {
	// Get the device code first to check expiry
	code, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}
	if code == nil {
		return ErrInvalidDeviceCode
	}

	// Calculate remaining TTL
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return ErrExpiredCode
	}

	// Marshal the token
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshaling token: %w", err)
	}

	// Save the token with the same expiry as the device code
	tokenKey := tokenPrefix + deviceCode
	if err := s.client.Set(ctx, tokenKey, data, ttl).Err(); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}

	return nil
}

// GetToken retrieves a stored token for a device code
func (s *RedisStore) GetToken(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	data, err := s.client.Get(ctx, tokenPrefix+deviceCode).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting token: %w", err)
	}

	var token TokenResponse
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("unmarshaling token: %w", err)
	}

	return &token, nil
}

// DeleteDeviceCode removes a device code and its associated data
func (s *RedisStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	// Get the device code to find the user code
	code, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}
	if code == nil {
		return nil // Already deleted
	}

	// Use pipeline to delete all related keys
	pipe := s.client.Pipeline()

	// Delete device code
	pipe.Del(ctx, devicePrefix+deviceCode)

	// Delete user code reference
	pipe.Del(ctx, userPrefix+normalizeCode(code.UserCode))

	// Delete token if exists
	pipe.Del(ctx, tokenPrefix+deviceCode)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("deleting device code: %w", err)
	}

	return nil
}
