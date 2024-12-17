package csrf

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const tokenPrefix = "csrf:"

// RedisStore implements the Store interface using Redis
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a new Redis-backed CSRF token store
func NewRedisStore(client *redis.Client) Store {
	return &RedisStore{client: client}
}

// SaveToken stores a CSRF token with expiration
func (s *RedisStore) SaveToken(ctx context.Context, token string, expiresIn time.Duration) error {
	if token == "" {
		return errors.New("empty token")
	}

	// Store the token with expiration
	key := tokenPrefix + token
	if err := s.client.Set(ctx, key, "1", expiresIn).Err(); err != nil {
		return fmt.Errorf("storing token: %w", err)
	}

	return nil
}

// ValidateToken checks if a token exists and has not expired
func (s *RedisStore) ValidateToken(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidToken
	}

	// Check if token exists
	key := tokenPrefix + token
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("checking token: %w", err)
	}
	if exists == 0 {
		return ErrInvalidToken
	}

	// Get TTL to check expiration
	ttl, err := s.client.TTL(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("checking token TTL: %w", err)
	}
	if ttl <= 0 {
		return ErrTokenExpired
	}

	return nil
}

// CheckHealth verifies Redis connectivity
func (s *RedisStore) CheckHealth(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis health check failed: %w", err)
	}
	return nil
}
