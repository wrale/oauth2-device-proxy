// Package deviceflow implements OAuth 2.0 Device Authorization Grant (RFC 8628)
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
	// MinExpiryDuration defines the minimum expiry duration per RFC 8628 section 6.1
	MinExpiryDuration = 10 * time.Minute // 10 minutes

	// MinPollInterval is the minimum interval between polling requests
	MinPollInterval = 5 * time.Second // 5 seconds

	// DefaultUserCodeLen is the default length for user codes
	DefaultUserCodeLen = 8 // Per RFC 8628 section 6.1
)

// Flow manages the device authorization flow
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

	// Validate user code before including in complete URI
	if err := validation.ValidateUserCode(userCode); err != nil {
		return verificationURI, ""
	}

	// Create verification URI with code as per RFC 8628 section 3.3.1
	query := url.Values{}
	query.Set("code", strings.TrimSpace(userCode))

	return verificationURI, verificationURI + "?" + query.Encode()
}

// RequestDeviceCode initiates a new device authorization flow
func (f *Flow) RequestDeviceCode(ctx context.Context, clientID, scope string) (*DeviceCode, error) {
	// Per RFC 8628 section 3.2, duration must provide sufficient time for user interaction
	expiresIn := int(f.expiryDuration.Seconds())
	if expiresIn < int(MinExpiryDuration.Seconds()) {
		expiresIn = int(MinExpiryDuration.Seconds())
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

	// Generate the device code
	deviceCode, err := generateSecureCode(32)
	if err != nil {
		return nil, fmt.Errorf("generating device code: %w", err)
	}

	// Generate the user code per RFC 8628 section 6.1
	userCode, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	// Build verification URIs per RFC 8628 section 3.2
	verificationURI, verificationURIComplete := f.buildVerificationURIs(userCode)

	code := &DeviceCode{
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
	}

	// Store the device code state
	if err := f.store.SaveDeviceCode(ctx, code); err != nil {
		return nil, fmt.Errorf("saving device code: %w", err)
	}

	return code, nil
}

// GetDeviceCode retrieves a device code by its device code string
func (f *Flow) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	code, err := f.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("getting device code: %w", err)
	}

	if code == nil {
		return nil, ErrInvalidDeviceCode
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	if remaining <= 0 {
		return nil, ErrExpiredCode
	}
	code.ExpiresIn = int(remaining)

	return code, nil
}

// VerifyUserCode verifies a user code and marks it as authorized
func (f *Flow) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	// Normalize and validate the user code
	normalizedCode := validation.NormalizeCode(userCode)
	if err := validation.ValidateUserCode(normalizedCode); err != nil {
		return nil, ErrInvalidUserCode
	}

	// Get the device code
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalizedCode)
	if err != nil {
		return nil, fmt.Errorf("getting device code: %w", err)
	}

	if code == nil {
		return nil, ErrInvalidUserCode
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	if remaining <= 0 {
		return nil, ErrExpiredCode
	}
	code.ExpiresIn = int(remaining)

	// Check rate limit for verification attempts per RFC 8628 section 5.2
	allowed, err := f.store.CheckDeviceCodeAttempts(ctx, code.DeviceCode)
	if err != nil {
		return nil, fmt.Errorf("checking rate limit: %w", err)
	}
	if !allowed {
		return nil, ErrRateLimitExceeded
	}

	return code, nil
}

// CheckDeviceCode checks the status of a device code
func (f *Flow) CheckDeviceCode(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	code, err := f.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("getting device code: %w", err)
	}

	if code == nil {
		return nil, ErrInvalidDeviceCode
	}

	// Check expiration
	remaining := time.Until(code.ExpiresAt).Seconds()
	if remaining <= 0 {
		return nil, ErrExpiredCode
	}
	code.ExpiresIn = int(remaining)

	// Check poll rate limiting per RFC 8628 section 3.5
	if !f.canPoll(code.LastPoll) {
		return nil, ErrSlowDown
	}

	// Update last poll time
	code.LastPoll = time.Now()
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

// CompleteAuthorization completes the device authorization by saving the token
func (f *Flow) CompleteAuthorization(ctx context.Context, deviceCode string, token *TokenResponse) error {
	code, err := f.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}

	if code == nil {
		return ErrInvalidDeviceCode
	}

	// Check expiration
	remaining := time.Until(code.ExpiresAt).Seconds()
	if remaining <= 0 {
		return ErrExpiredCode
	}
	code.ExpiresIn = int(remaining)

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
