// Package deviceflow implements device authorization storage with Redis
package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

const (
	devicePrefix    = "device:"
	userPrefix      = "user:"
	tokenPrefix     = "token:"
	ratePrefix      = "rate:"
	pollPrefix      = "poll:"
	maxAttempts     = 50  // Maximum verification attempts per device code per RFC 8628 section 5.2
	rateLimitWindow = 5   // Time window in minutes for rate limit tracking
	errorBackoff    = 300 // Error backoff in seconds when rate limit exceeded (per RFC 8628)
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

	// Use pipeline to set all keys atomically
	pipe := s.client.Pipeline()

	// Set device code with expiry
	deviceKey := devicePrefix + code.DeviceCode
	pipe.Set(ctx, deviceKey, data, ttl)

	// Set user code reference
	userKey := userPrefix + validation.NormalizeCode(code.UserCode)
	pipe.Set(ctx, userKey, code.DeviceCode, ttl)

	// Initialize rate limit tracking
	timeKey := fmt.Sprintf("%s%s:time", ratePrefix, code.DeviceCode)
	pipe.Expire(ctx, timeKey, ttl) // Ensure cleanup

	// Execute all operations
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
	// Get device code from user code reference
	deviceCode, err := s.client.Get(ctx, userPrefix+validation.NormalizeCode(userCode)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting user code reference: %w", err)
	}

	return s.GetDeviceCode(ctx, deviceCode)
}

// SaveTokenResponse stores a token response for a device code per RFC 8628
func (s *RedisStore) SaveTokenResponse(ctx context.Context, deviceCode string, token *TokenResponse) error {
	// Verify device code exists
	code, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}
	if code == nil {
		return ErrInvalidDeviceCode
	}

	// Check expiry
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return ErrExpiredCode
	}

	// Marshal token
	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshaling token response: %w", err)
	}

	// Use pipeline for atomic update
	pipe := s.client.Pipeline()

	// Save token with device code expiry
	tokenKey := tokenPrefix + deviceCode
	pipe.Set(ctx, tokenKey, data, ttl)

	// Clean up rate limit data on success
	timeKey := fmt.Sprintf("%s%s:time", ratePrefix, deviceCode)
	pollKey := fmt.Sprintf("%s%s", pollPrefix, deviceCode)
	pipe.Del(ctx, timeKey, pollKey)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("saving token response: %w", err)
	}

	return nil
}

// GetTokenResponse retrieves a stored token response for a device code
func (s *RedisStore) GetTokenResponse(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	data, err := s.client.Get(ctx, tokenPrefix+deviceCode).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting token response: %w", err)
	}

	var token TokenResponse
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("unmarshaling token response: %w", err)
	}

	return &token, nil
}

// DeleteDeviceCode removes a device code and associated data
func (s *RedisStore) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	// Get code first for user code cleanup
	code, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}
	if code == nil {
		return nil // Already deleted
	}

	// Delete all associated keys atomically
	pipe := s.client.Pipeline()

	// Main keys
	pipe.Del(ctx, devicePrefix+deviceCode)
	pipe.Del(ctx, userPrefix+validation.NormalizeCode(code.UserCode))
	pipe.Del(ctx, tokenPrefix+deviceCode)

	// Rate limit keys
	timeKey := fmt.Sprintf("%s%s:time", ratePrefix, deviceCode)
	pollKey := fmt.Sprintf("%s%s", pollPrefix, deviceCode)
	pipe.Del(ctx, timeKey, pollKey)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("deleting device code: %w", err)
	}

	return nil
}

// GetPollCount gets the number of polls in the given window
func (s *RedisStore) GetPollCount(ctx context.Context, deviceCode string, window time.Duration) (int, error) {
	pollKey := fmt.Sprintf("%s%s", pollPrefix, deviceCode)
	windowSecs := int64(window.Seconds())
	now := time.Now().Unix()
	min := fmt.Sprintf("%d", now-windowSecs)

	// Get count of polls in window using sorted set
	count, err := s.client.ZCount(ctx, pollKey, min, fmt.Sprintf("%d", now)).Result()
	if err != nil {
		return 0, fmt.Errorf("getting poll count: %w", err)
	}

	return int(count), nil
}

// UpdatePollTimestamp updates the last poll timestamp
func (s *RedisStore) UpdatePollTimestamp(ctx context.Context, deviceCode string) error {
	code, err := s.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}
	if code == nil {
		return ErrInvalidDeviceCode
	}

	code.LastPoll = time.Now()
	return s.SaveDeviceCode(ctx, code)
}

// IncrementPollCount increments the poll counter with timestamp
func (s *RedisStore) IncrementPollCount(ctx context.Context, deviceCode string) error {
	pollKey := fmt.Sprintf("%s%s", pollPrefix, deviceCode)
	now := time.Now().Unix()

	// Add poll with score = timestamp
	err := s.client.ZAdd(ctx, pollKey, redis.Z{
		Score:  float64(now),
		Member: strconv.FormatInt(now, 10),
	}).Err()
	if err != nil {
		return fmt.Errorf("incrementing poll count: %w", err)
	}

	// Set expiry on first poll
	if err := s.client.Expire(ctx, pollKey, rateLimitWindow*time.Minute).Err(); err != nil {
		return fmt.Errorf("setting poll key expiry: %w", err)
	}

	return nil
}
