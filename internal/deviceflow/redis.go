// Package deviceflow implements device authorization storage with Redis
package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

const (
	devicePrefix    = "device:"
	userPrefix      = "user:"
	tokenPrefix     = "token:"
	ratePrefix      = "rate:"
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
	backoffKey := fmt.Sprintf("%s%s:backoff", ratePrefix, code.DeviceCode)
	pipe.Del(ctx, timeKey, backoffKey) // Clean start
	pipe.Expire(ctx, timeKey, ttl)     // Ensure cleanup

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

// SaveToken stores an access token for a device code
func (s *RedisStore) SaveToken(ctx context.Context, deviceCode string, token *TokenResponse) error {
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
		return fmt.Errorf("marshaling token: %w", err)
	}

	// Use pipeline for atomic update
	pipe := s.client.Pipeline()

	// Save token with device code expiry
	tokenKey := tokenPrefix + deviceCode
	pipe.Set(ctx, tokenKey, data, ttl)

	// Clean up rate limit data on success
	timeKey := fmt.Sprintf("%s%s:time", ratePrefix, deviceCode)
	backoffKey := fmt.Sprintf("%s%s:backoff", ratePrefix, deviceCode)
	pipe.Del(ctx, timeKey, backoffKey)

	if _, err := pipe.Exec(ctx); err != nil {
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
	backoffKey := fmt.Sprintf("%s%s:backoff", ratePrefix, deviceCode)
	pipe.Del(ctx, timeKey, backoffKey)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("deleting device code: %w", err)
	}

	return nil
}

// CheckDeviceCodeAttempts implements rate limiting for device code verification per RFC 8628 section 5.2
// Uses Redis sorted sets for accurate sliding window tracking with exponential backoff
func (s *RedisStore) CheckDeviceCodeAttempts(ctx context.Context, deviceCode string) (bool, error) {
	// Get keys for atomic operations
	deviceKey := devicePrefix + deviceCode
	timeKey := fmt.Sprintf("%s%s:time", ratePrefix, deviceCode)
	backoffKey := fmt.Sprintf("%s%s:backoff", ratePrefix, deviceCode)
	now := time.Now().Unix()

	// Use pipeline for atomic operations
	pipe := s.client.Pipeline()

	// Check device code exists
	pipe.Exists(ctx, deviceKey)

	// Check if in backoff period
	pipe.Get(ctx, backoffKey)

	// Log attempt in sorted set
	pipe.ZAdd(ctx, timeKey, redis.Z{
		Score:  float64(now),
		Member: now,
	})

	// Calculate sliding window
	windowStart := now - int64(rateLimitWindow*60)

	// Remove old attempts outside window
	pipe.ZRemRangeByScore(ctx, timeKey, "-inf", fmt.Sprintf("%d", windowStart))

	// Count attempts in current window
	countCmd := pipe.ZCount(ctx, timeKey, fmt.Sprintf("%d", windowStart), fmt.Sprintf("%d", now))

	// Execute all checks atomically
	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("executing rate limit check: %w", err)
	}

	// Verify device code exists
	exists, err := cmders[0].(*redis.IntCmd).Result()
	if err != nil {
		return false, fmt.Errorf("checking device code existence: %w", err)
	}
	if exists == 0 {
		return false, nil
	}

	// Check if in backoff period
	backoffResult := cmders[1].(*redis.StringCmd)
	if backoffResult.Err() == nil {
		// Still in backoff period
		return false, nil
	} else if !errors.Is(backoffResult.Err(), redis.Nil) {
		return false, fmt.Errorf("checking backoff status: %w", backoffResult.Err())
	}

	// Get attempt count
	count, err := countCmd.Result()
	if err != nil {
		return false, fmt.Errorf("getting attempt count: %w", err)
	}

	// Check against limit
	allowed := count <= maxAttempts
	if !allowed {
		// Set backoff period
		if err := s.client.Set(ctx, backoffKey, now, time.Duration(errorBackoff)*time.Second).Err(); err != nil {
			return false, fmt.Errorf("setting backoff period: %w", err)
		}

		// Log for monitoring
		blockedKey := fmt.Sprintf("%s%s:blocked", ratePrefix, deviceCode)
		if err := s.client.Incr(ctx, blockedKey).Err(); err != nil {
			return false, fmt.Errorf("incrementing blocked counter: %w", err)
		}
	}

	return allowed, nil
}
