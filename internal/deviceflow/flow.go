// Package deviceflow implements OAuth 2.0 Device Authorization Grant per RFC 8628
package deviceflow

import (
	"context"
	"fmt"
	"time"
)

const (
	// MinExpiryDuration defines the minimum expiry duration per RFC 8628
	MinExpiryDuration = 10 * time.Minute

	// MinPollInterval is the minimum interval between polling requests
	MinPollInterval = 5 * time.Second

	// DeviceCodeLength is the required length of the device code in hex characters
	DeviceCodeLength = 64 // 32 bytes hex encoded per tests
)

// Flow manages the device authorization grant flow per RFC 8628
type Flow struct {
	store           Store
	baseURL         string
	expiryDuration  time.Duration
	pollInterval    time.Duration
	userCodeLength  int
	rateLimitWindow time.Duration
	maxPollsPerMin  int
}

// NewFlow creates a new device flow manager with provided options
func NewFlow(store Store, baseURL string, opts ...Option) *Flow {
	f := newDefaultFlow(store, baseURL)
	for _, opt := range opts {
		opt(f)
	}

	// Ensure minimum durations per RFC 8628
	if f.expiryDuration < MinExpiryDuration {
		f.expiryDuration = MinExpiryDuration
	}
	if f.pollInterval < MinPollInterval {
		f.pollInterval = MinPollInterval
	}

	return f
}

// RequestDeviceCode initiates a new device authorization flow
func (f *Flow) RequestDeviceCode(ctx context.Context, clientID, scope string) (*DeviceCode, error) {
	// Calculate expiry time - must be at least 10 minutes per RFC 8628
	expiresIn := int(f.expiryDuration.Seconds())
	if expiresIn < int(MinExpiryDuration.Seconds()) {
		expiresIn = int(MinExpiryDuration.Seconds())
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

	// Generate device code - must be 64 hex chars (32 bytes) per tests
	deviceCode, err := generateSecureCode(DeviceCodeLength)
	if err != nil {
		return nil, fmt.Errorf("generating device code: %w", err)
	}

	// Generate user code meeting RFC 8628 section 6.1 requirements
	userCode, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	// Build verification URIs
	verificationURI, verificationURIComplete := f.buildVerificationURIs(userCode)

	return &DeviceCode{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               expiresIn,
		Interval:                int(f.pollInterval.Seconds()),
		ExpiresAt:               expiresAt,
		ClientID:                clientID,
		Scope:                   scope,
		LastPoll:                now,
	}, nil
}

// GetDeviceCode retrieves and validates a device code per RFC 8628.
// It enforces consistent validation and expiry handling across all device code operations.
func (f *Flow) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	// First check store errors - these take precedence
	code, err := f.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("getting device code: %w", err)
	}

	// Check existence before other validations
	if code == nil {
		return nil, ErrInvalidDeviceCode
	}

	// Check expiration using direct time comparison for precision
	if time.Now().After(code.ExpiresAt) {
		return nil, ErrExpiredCode
	}

	// Update ExpiresIn based on remaining time
	code.ExpiresIn = int(time.Until(code.ExpiresAt).Seconds())

	return code, nil
}

// CheckHealth verifies the flow manager's storage backend is healthy
func (f *Flow) CheckHealth(ctx context.Context) error {
	return f.store.CheckHealth(ctx)
}
