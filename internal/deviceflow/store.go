// Package deviceflow implements OAuth 2.0 Device Authorization Grant (RFC 8628)
package deviceflow

import (
	"context"
	"time"
)

// Store defines the interface for device flow storage
type Store interface {
	// SaveDeviceCode stores a device code with its associated data
	SaveDeviceCode(ctx context.Context, code *DeviceCode) error

	// GetDeviceCode retrieves a device code by its device code string
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// GetDeviceCodeByUserCode retrieves a device code by its user code
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)

	// GetTokenResponse retrieves token response for a device code
	GetTokenResponse(ctx context.Context, deviceCode string) (*TokenResponse, error)

	// SaveTokenResponse stores token response for a device code
	SaveTokenResponse(ctx context.Context, deviceCode string, token *TokenResponse) error

	// DeleteDeviceCode removes a device code and its associated data
	DeleteDeviceCode(ctx context.Context, deviceCode string) error

	// GetPollCount gets the number of polls in the given window
	GetPollCount(ctx context.Context, deviceCode string, window time.Duration) (int, error)

	// UpdatePollTimestamp updates the last poll timestamp for rate limiting
	UpdatePollTimestamp(ctx context.Context, deviceCode string) error

	// IncrementPollCount increments the poll counter for rate limiting
	IncrementPollCount(ctx context.Context, deviceCode string) error

	// CheckHealth verifies the storage backend is healthy
	CheckHealth(ctx context.Context) error
}
