package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	devicePrefix    = "device:"
	userPrefix      = "user:"
	tokenPrefix     = "token:"
	ratePrefix      = "rate:"
	maxAttempts     = 50 // Maximum verification attempts per device code per RFC 8628
	rateLimitWindow = 5  // Time window in minutes for rate limit tracking
)

// RedisStore implements the Store interface using Redis
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a new Redis-backed store
func NewRedisStore(client *redis.Client) Store {
	return &RedisStore{client: client}
}

// CheckHealth verifies Redis connectivity
func (s *RedisStore) CheckHealth(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis health check failed: %w", err)
	}
	return nil
}

// SaveDeviceCode stores a device code with expiration
func (s *RedisStore) SaveDeviceCode(ctx context.Context, code *DeviceCode) error {
	// Calculate TTL based on expiry time
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return errors.New("code has already expired")
	}

	// Marshal the device code
	data, err := json.Marshal(code)
	if err != nil {
		return fmt.Errorf("marshaling device code: %w", err)
	}

	// Use a transaction to set both device and user code keys
	pipe := s.client.Pipeline()

	// Set the device code
	deviceKey := devicePrefix + code.DeviceCode
	pipe.Set(ctx, deviceKey, data, ttl)

	// Set the user code reference
	userKey := userPrefix + normalizeCode(code.UserCode)
	pipe.Set(ctx, userKey, code.DeviceCode, ttl)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("saving device code: %w", err)
	}

	return nil
}

// GetDeviceCode retrieves a device code
func (s *RedisStore) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	data, err := s.client.Get(ctx, devicePrefix+deviceCode).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting device code: %w", err)
	}

	var code DeviceCode
	if err := json.Unmarshal(data, &code); err != nil {
		return nil, fmt.Errorf("unmarshaling device code: %w", err)
	}

	return &code, nil
}

// GetDeviceCodeByUserCode retrieves a device code using the user code
func (s *RedisStore) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	// Get the device code from the user code reference
	deviceCode, err := s.client.Get(ctx, userPrefix+normalizeCode(userCode)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting user code reference: %w", err)
	}

	// Get the full device code data
	return s.GetDeviceCode(ctx, deviceCode)
}

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

	// Delete rate limit key
	pipe.Del(ctx, ratePrefix+deviceCode)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("deleting device code: %w", err)
	}

	return nil
}

// CheckDeviceCodeAttempts increments and checks the rate limit for device code verification attempts
// Returns true if the attempt is allowed, false if the rate limit is exceeded
func (s *RedisStore) CheckDeviceCodeAttempts(ctx context.Context, deviceCode string) (bool, error) {
	key := ratePrefix + deviceCode
	window := time.Duration(rateLimitWindow) * time.Minute

	// Use pipeline to increment and check atomically
	pipe := s.client.Pipeline()

	// Increment counter
	incrCmd := pipe.Incr(ctx, key)

	// Ensure expiry is set (in case of new key)
	pipe.Expire(ctx, key, window)

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return false, fmt.Errorf("checking rate limit: %w", err)
	}

	// Get the count (from the increment operation)
	count, err := incrCmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, fmt.Errorf("getting rate limit count: %w", err)
	}

	// Allow the attempt if under the limit
	return count <= maxAttempts, nil
}
