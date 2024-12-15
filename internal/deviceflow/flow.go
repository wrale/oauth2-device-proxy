// Package deviceflow implements OAuth 2.0 Device Authorization Grant (RFC 8628)
package deviceflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jmdots/oauth2-device-proxy/internal/validation"
)

// Common errors
var (
	ErrInvalidDeviceCode    = errors.New("invalid device code")
	ErrInvalidUserCode      = errors.New("invalid user code")
	ErrPendingAuthorization = errors.New("authorization pending")
	ErrSlowDown             = errors.New("polling too frequently")
	ErrExpiredCode          = errors.New("code expired")
	ErrRateLimitExceeded    = errors.New("verification attempts exceeded, per RFC 8628 section 5.2")
)

// DeviceCode represents the device authorization details per RFC 8628 section 3.2
type DeviceCode struct {
	// Required fields per RFC 8628 section 3.2
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"` // RFC 8628 response field
	Interval        int    `json:"interval"`

	// Optional verification_uri_complete field per RFC 8628 section 3.3.1
	// Enables non-textual transmission of the verification URI (e.g., QR codes)
	// The URI includes the user code to minimize user input required
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// Additional fields for internal tracking
	ExpiresAt time.Time `json:"-"` // Internal tracking
	ClientID  string    `json:"-"`
	Scope     string    `json:"-"`
	LastPoll  time.Time `json:"-"`
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

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
	f := &Flow{
		store:           store,
		baseURL:         baseURL,
		expiryDuration:  15 * time.Minute,
		pollInterval:    5 * time.Second,
		userCodeLength:  validation.MinLength, // Use validation package constants
		rateLimitWindow: time.Minute,
		maxPollsPerMin:  12,
	}

	for _, opt := range opts {
		opt(f)
	}

	return f
}

// Option configures the device flow
type Option func(*Flow)

// WithExpiryDuration sets the code expiry duration
func WithExpiryDuration(d time.Duration) Option {
	return func(f *Flow) {
		f.expiryDuration = d
	}
}

// WithPollInterval sets the minimum polling interval
func WithPollInterval(d time.Duration) Option {
	return func(f *Flow) {
		f.pollInterval = d
	}
}

// WithUserCodeLength sets the user code length
func WithUserCodeLength(length int) Option {
	return func(f *Flow) {
		f.userCodeLength = length
	}
}

// WithRateLimit sets rate limiting parameters
func WithRateLimit(window time.Duration, maxPolls int) Option {
	return func(f *Flow) {
		f.rateLimitWindow = window
		f.maxPollsPerMin = maxPolls
	}
}

// RequestDeviceCode initiates a new device authorization flow
func (f *Flow) RequestDeviceCode(ctx context.Context, clientID, scope string) (*DeviceCode, error) {
	// Calculate and validate expiry duration per RFC 8628 section 3.2
	expiresIn := int(f.expiryDuration.Seconds())
	if expiresIn <= f.userCodeLength*2 {
		// Double the minimum user code length per RFC 8628
		expiresIn = f.userCodeLength * 2
	}

	// Calculate expiry timestamp from validated expiresIn
	expiresAt := time.Now().Add(time.Duration(expiresIn) * time.Second)

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

	// Construct verification_uri_complete per RFC 8628 section 3.3.1
	values := url.Values{"code": {userCode}}
	verificationURIComplete := verificationURI + "?" + values.Encode()

	code := &DeviceCode{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURIComplete,
		ExpiresIn:               expiresIn, // Required by RFC 8628
		ExpiresAt:               expiresAt, // Internal tracking
		Interval:                int(f.pollInterval.Seconds()),
		ClientID:                clientID,
		Scope:                   scope,
		LastPoll:                time.Now(),
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

	if time.Now().After(code.ExpiresAt) {
		return nil, ErrExpiredCode
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

	if time.Now().After(code.ExpiresAt) {
		return nil, ErrExpiredCode
	}

	// Check rate limit for verification attempts per RFC 8628 section 5.2
	allowed, err := f.store.CheckDeviceCodeAttempts(ctx, code.DeviceCode)
	if err != nil {
		return nil, fmt.Errorf("checking rate limit: %w", err)
	}
	if !allowed {
		return nil, ErrRateLimitExceeded
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	if remaining <= 0 {
		return nil, ErrExpiredCode
	}
	code.ExpiresIn = int(remaining)

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

	if time.Now().After(code.ExpiresAt) {
		return nil, ErrExpiredCode
	}

	// Check poll rate limiting
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

// CompleteAuthorization completes the authorization by saving the token
func (f *Flow) CompleteAuthorization(ctx context.Context, deviceCode string, token *TokenResponse) error {
	code, err := f.store.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return fmt.Errorf("getting device code: %w", err)
	}

	if code == nil {
		return ErrInvalidDeviceCode
	}

	if time.Now().After(code.ExpiresAt) {
		return ErrExpiredCode
	}

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

func generateSecureCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// selectChar chooses a random available character that hasn't exceeded maxAllowed frequency
func selectChar(charset []byte, freqs map[byte]int, maxAllowed int) (byte, error) {
	// Create list of available characters that haven't hit max frequency
	available := make([]byte, 0, len(charset))
	for _, c := range charset {
		if freqs[c] < maxAllowed {
			available = append(available, c)
		}
	}

	if len(available) == 0 {
		return 0, fmt.Errorf("no characters available under frequency limit %d", maxAllowed)
	}

	// Generate random index
	randByte := make([]byte, 1)
	if _, err := rand.Read(randByte); err != nil {
		return 0, err
	}

	// Select and track character
	selected := available[int(randByte[0])%len(available)]
	freqs[selected]++

	return selected, nil
}

// generateUserCode generates a user-friendly code per RFC 8628 section 6.1
func generateUserCode() (string, error) {
	maxAttempts := 100 // Prevent infinite loops
	maxAllowed := 2    // Maximum times a character can appear per RFC 8628

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Pre-allocate exactly the needed space (4 chars + hyphen + 4 chars)
		code := make([]byte, validation.MinLength+1)
		freqs := make(map[byte]int)
		valid := true

		// Fill first half
		for i := 0; i < validation.MinGroupSize && valid; i++ {
			char, err := selectChar([]byte(validation.ValidCharset), freqs, maxAllowed)
			if err != nil {
				valid = false
				break
			}
			code[i] = char
		}

		// Add separator
		code[validation.MinGroupSize] = '-'

		// Fill second half
		for i := 0; i < validation.MinGroupSize && valid; i++ {
			char, err := selectChar([]byte(validation.ValidCharset), freqs, maxAllowed)
			if err != nil {
				valid = false
				break
			}
			code[validation.MinGroupSize+1+i] = char
		}

		if valid {
			generated := string(code)
			if err := validation.ValidateUserCode(generated); err == nil {
				return generated, nil
			}
		}
	}

	return "", fmt.Errorf("failed to generate valid code after %d attempts", maxAttempts)
}

// normalizeCode converts a user code to storage format
func normalizeCode(code string) string {
	return validation.NormalizeCode(code)
}
