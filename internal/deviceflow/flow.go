// Package deviceflow implements OAuth 2.0 Device Authorization Grant (RFC 8628)
package deviceflow

import (
	"context"
	"fmt"
	"time"

	"github.com/jmdots/oauth2-device-proxy/internal/validation"
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

// NewFlow creates a new device flow manager
func NewFlow(store Store, baseURL string, opts ...Option) *Flow {
	f := newDefaultFlow(store, baseURL)
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// RequestDeviceCode initiates a new device authorization flow
func (f *Flow) RequestDeviceCode(ctx context.Context, clientID, scope string) (*DeviceCode, error) {
	// Calculate expiry time per RFC 8628 section 3.2
	// Duration must provide sufficient time for user interaction
	// Minimum duration is 10 minutes per section 6.1
	expiresIn := int(f.expiryDuration.Seconds())
	minDuration := 600 // 10 minutes in seconds
	if expiresIn < minDuration {
		expiresIn = minDuration
	}

	// Set absolute expiry time based on calculated duration
	now := time.Now()
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

	// Generate device code
	deviceCode, err := generateSecureCode(32)
	if err != nil {
		return nil, fmt.Errorf("generating device code: %w", err)
	}

	// Generate user code with RFC 8628 section 6.1 compliant character set
	userCode, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	verificationURI := f.baseURL + "/device"

	// Build verification_uri_complete without URL encoding to avoid null bytes
	// Format per RFC 8628 section 3.3.1, using simple path joining
	verificationURIComplete := verificationURI
	if err := validation.ValidateUserCode(userCode); err == nil {
		verificationURIComplete = verificationURI + "?code=" + userCode
	}

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
	// Get the device code first
	code, err := f.store.GetDeviceCodeByUserCode(ctx, validation.NormalizeCode(userCode))
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

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	if remaining <= 0 {
		return nil, ErrExpiredCode
	}
	code.ExpiresIn = int(remaining)

	// Check poll rate limiting
	if !f.canPoll(code.LastPoll) {
		return nil, ErrSlowDown
	}

	// Update last poll time and ExpiresIn
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

// CompleteAuthorization completes the authorization by saving the token
func (f *Flow) CompleteAuthorization(ctx context.Context, deviceCode string, token *TokenResponse) error {
	code, err := f.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}

	if code == nil {
		return ErrInvalidDeviceCode
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	if remaining <= 0 {
		return ErrExpiredCode
	}
	code.ExpiresIn = int(remaining)

	if err := f.store.SaveToken(ctx, deviceCode, token); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}

	return nil
}

// CheckHealth verifies the flow manager's storage backend is healthy
func (f *Flow) CheckHealth(ctx context.Context) error {
	return f.store.CheckHealth(ctx)
}

// Helper functions

func (f *Flow) canPoll(lastPoll time.Time) bool {
	return time.Since(lastPoll) >= f.pollInterval
}
