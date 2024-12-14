package deviceflow

import (
	"context"
)

// Store defines the interface for device flow storage
type Store interface {
	// SaveDeviceCode stores a device code with its associated data
	SaveDeviceCode(ctx context.Context, code *DeviceCode) error

	// GetDeviceCode retrieves a device code by its device code string
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// GetDeviceCodeByUserCode retrieves a device code by its user code
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)

	// SaveToken stores an access token for a device code
	SaveToken(ctx context.Context, deviceCode string, token *TokenResponse) error

	// GetToken retrieves a stored token for a device code
	GetToken(ctx context.Context, deviceCode string) (*TokenResponse, error)

	// DeleteDeviceCode removes a device code and its associated data
	DeleteDeviceCode(ctx context.Context, deviceCode string) error

	// CheckHealth verifies the storage backend is healthy
	CheckHealth(ctx context.Context) error
}
