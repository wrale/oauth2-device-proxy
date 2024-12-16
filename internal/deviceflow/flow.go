// Package deviceflow implements OAuth 2.0 Device Authorization Grant per RFC 8628
package deviceflow

import (
	"context"
	"net/url"
	"path"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

const (
	// MinExpiryDuration defines the minimum expiry duration per RFC 8628
	MinExpiryDuration = 10 * time.Minute

	// MinPollInterval is the minimum interval between polling requests
	MinPollInterval = 5 * time.Second

	// DeviceCodeLength is the required length of the device code in hex characters
	DeviceCodeLength = 64 // 32 bytes hex encoded per tests
)

// Flow defines the interface for device authorization grant flow per RFC 8628
type Flow interface {
	// RequestDeviceCode initiates a new device authorization request
	RequestDeviceCode(ctx context.Context, clientID string, scope string) (*DeviceCode, error)

	// GetDeviceCode retrieves and validates a device code
	GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// CheckDeviceCode validates device code and returns token if authorized
	CheckDeviceCode(ctx context.Context, deviceCode string) (*TokenResponse, error)

	// VerifyUserCode validates user code and returns associated device code
	VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error)

	// CompleteAuthorization completes the authorization flow for a device code
	CompleteAuthorization(ctx context.Context, deviceCode string, token *TokenResponse) error

	// CheckHealth verifies the flow manager's storage backend is healthy
	CheckHealth(ctx context.Context) error
}

// flowImpl implements the Flow interface using provided storage
type flowImpl struct {
	store           Store
	baseURL         string
	expiryDuration  time.Duration
	pollInterval    time.Duration
	userCodeLength  int
	rateLimitWindow time.Duration
	maxPollsPerMin  int
}

// NewFlow creates a new device flow manager with provided options
func NewFlow(store Store, baseURL string, opts ...Option) Flow {
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

func newDefaultFlow(store Store, baseURL string) *flowImpl {
	return &flowImpl{
		store:           store,
		baseURL:         baseURL,
		expiryDuration:  MinExpiryDuration,
		pollInterval:    MinPollInterval,
		userCodeLength:  8,
		rateLimitWindow: time.Minute,
		maxPollsPerMin:  12,
	}
}

// RequestDeviceCode initiates a new device authorization flow
func (f *flowImpl) RequestDeviceCode(ctx context.Context, clientID, scope string) (*DeviceCode, error) {
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
		return nil, err
	}

	// Generate user code meeting RFC 8628 section 6.1 requirements
	userCode, err := generateUserCode()
	if err != nil {
		return nil, err
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
func (f *flowImpl) GetDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error) {
	// First check store errors - these take precedence
	code, err := f.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, err
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

// CheckDeviceCode validates device code and returns token if authorized
func (f *flowImpl) CheckDeviceCode(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	code, err := f.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, err
	}

	// Get cached token response if it exists
	token, err := f.store.GetTokenResponse(ctx, deviceCode)
	if err != nil {
		return nil, err
	}

	// If no token yet, check rate limiting
	if token == nil {
		// Ensure minimum polling interval
		if time.Since(code.LastPoll) < f.pollInterval {
			return nil, ErrSlowDown
		}

		// Check rate limit window
		if f.maxPollsPerMin > 0 {
			count, err := f.store.GetPollCount(ctx, deviceCode, f.rateLimitWindow)
			if err != nil {
				return nil, err
			}
			if count >= f.maxPollsPerMin {
				return nil, ErrSlowDown
			}
		}

		// Update poll timestamp and count
		if err := f.store.UpdatePollTimestamp(ctx, deviceCode); err != nil {
			return nil, err
		}
		if err := f.store.IncrementPollCount(ctx, deviceCode); err != nil {
			return nil, err
		}

		// Return pending error
		return nil, ErrPendingAuthorization
	}

	// Return successful token response
	return token, nil
}

// CompleteAuthorization completes the flow with token response
func (f *flowImpl) CompleteAuthorization(ctx context.Context, deviceCode string, token *TokenResponse) error {
	return f.store.SaveTokenResponse(ctx, deviceCode, token)
}

// CheckHealth verifies the storage backend is healthy
func (f *flowImpl) CheckHealth(ctx context.Context) error {
	return f.store.CheckHealth(ctx)
}

// buildVerificationURIs creates the verification URIs per RFC 8628 sections 3.2 and 3.3.1
// It returns both the base verification URI and the complete URI that includes the user code:
// - verification_uri: The base URI that users can visit to enter their code
// - verification_uri_complete: Optional URI that includes the user code (e.g., for QR codes)
func (f *flowImpl) buildVerificationURIs(userCode string) (string, string) {
	// Parse the base URL to properly handle existing paths
	baseURL, err := url.Parse(f.baseURL)
	if err != nil {
		return "", "" // Invalid base URL
	}

	// Combine existing path with device endpoint
	baseURL.Path = path.Join(baseURL.Path, "device")
	verificationURI := baseURL.String()

	// Validate the user code
	if err := validation.ValidateUserCode(userCode); err != nil {
		return verificationURI, "" // Return base URI only if code invalid
	}

	// Create verification URI with code per RFC section 3.3.1
	completeURL := *baseURL // Make a copy for the complete URI
	q := completeURL.Query()
	q.Set("code", userCode) // Use display format per RFC section 6.1
	completeURL.RawQuery = q.Encode()

	return verificationURI, completeURL.String()
}
