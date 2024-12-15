// Package deviceflow implements OAuth 2.0 Device Authorization Grant per RFC 8628
package deviceflow

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jmdots/oauth2-device-proxy/internal/validation"
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

// buildVerificationURIs creates the verification URIs per RFC 8628 sections 3.2 and 3.3.1
func (f *Flow) buildVerificationURIs(userCode string) (string, string) {
	// Ensure base URL ends with no trailing slash
	baseURL := strings.TrimSuffix(f.baseURL, "/")
	verificationURI := baseURL + "/device"

	// Only include code in complete URI if it's valid
	if err := validation.ValidateUserCode(userCode); err != nil {
		return verificationURI, "" // Return base URI only if code invalid
	}

	// Create verification URI with code per RFC section 3.3.1
	query := url.Values{}
	query.Set("code", userCode) // Use display format
	completePath := verificationURI + "?" + query.Encode()

	return verificationURI, completePath
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

// VerifyUserCode verifies a user code and checks rate limiting.
// Error checking order per RFC 8628:
// 1. Store errors take precedence
// 2. Check if code exists
// 3. Check expiration
// 4. Check rate limiting
// 5. Validate code format
func (f *Flow) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	normalized := validation.NormalizeCode(userCode)

	// First check store errors - these take precedence
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		return nil, err // Storage errors pass through unchanged
	}

	// Code not found - validate format for helpful error
	if code == nil {
		if err := validation.ValidateUserCode(userCode); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUserCode, err)
		}
		return nil, ErrInvalidUserCode
	}

	// Code exists - check expiration first
	if time.Now().After(code.ExpiresAt) {
		return nil, ErrExpiredCode
	}

	// Check rate limiting per RFC 8628 section 5.2
	allowed, err := f.store.CheckDeviceCodeAttempts(ctx, code.DeviceCode)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrRateLimitExceeded
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	code.ExpiresIn = int(remaining)

	return code, nil
}

// CheckDeviceCode checks device code status per RFC 8628 section 3.4
func (f *Flow) CheckDeviceCode(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	// Use GetDeviceCode for consistent validation
	code, err := f.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, err
	}

	// Check rate limiting per RFC 8628 section 3.5
	if !f.canPoll(code.LastPoll) {
		return nil, ErrSlowDown
	}

	// Update last poll time
	code.LastPoll = time.Now()
	code.ExpiresIn = int(time.Until(code.ExpiresAt).Seconds())
	if err := f.store.SaveDeviceCode(ctx, code); err != nil {
		return nil, fmt.Errorf("updating last poll time: %w", err)
	}

	// Check if token exists
	token, err := f.store.GetToken(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("getting token: %w", err)
	}

	if token == nil {
		return nil, ErrPendingAuthorization
	}

	return token, nil
}

// CompleteAuthorization completes device authorization by saving the token
func (f *Flow) CompleteAuthorization(ctx context.Context, deviceCode string, token *TokenResponse) error {
	// Use GetDeviceCode for consistent validation
	code, err := f.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return err
	}

	// Save the token
	if err := f.store.SaveToken(ctx, deviceCode, token); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}

	return nil
}

// CheckHealth verifies the flow manager's storage backend is healthy
func (f *Flow) CheckHealth(ctx context.Context) error {
	return f.store.CheckHealth(ctx)
}

// canPoll determines if polling is allowed based on the interval
func (f *Flow) canPoll(lastPoll time.Time) bool {
	return time.Since(lastPoll) >= f.pollInterval
}
