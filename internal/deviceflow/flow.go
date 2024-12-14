package deviceflow

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Common errors
var (
	ErrInvalidDeviceCode    = errors.New("invalid device code")
	ErrInvalidUserCode      = errors.New("invalid user code")
	ErrPendingAuthorization = errors.New("authorization pending")
	ErrSlowDown             = errors.New("polling too frequently")
	ErrExpiredCode          = errors.New("code expired")
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
)

// DeviceCode represents the device authorization details
type DeviceCode struct {
	DeviceCode      string    `json:"device_code"`
	UserCode        string    `json:"user_code"`
	VerificationURI string    `json:"verification_uri"`
	ExpiresAt       time.Time `json:"expires_at"`
	Interval        int       `json:"interval"`
	ClientID        string    `json:"client_id"`
	Scope           string    `json:"scope,omitempty"`
	LastPoll        time.Time `json:"last_poll"`
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
		userCodeLength:  8,
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
	deviceCode, err := generateSecureCode(32)
	if err != nil {
		return nil, fmt.Errorf("generating device code: %w", err)
	}

	userCode, err := generateUserCode(f.userCodeLength)
	if err != nil {
		return nil, fmt.Errorf("generating user code: %w", err)
	}

	code := &DeviceCode{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: f.baseURL + "/device",
		ExpiresAt:       time.Now().Add(f.expiryDuration),
		Interval:        int(f.pollInterval.Seconds()),
		ClientID:        clientID,
		Scope:           scope,
		LastPoll:        time.Now(),
	}

	if err := f.store.SaveDeviceCode(ctx, code); err != nil {
		return nil, fmt.Errorf("saving device code: %w", err)
	}

	return code, nil
}

// VerifyUserCode verifies a user code and marks it as authorized
func (f *Flow) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalizeCode(userCode))
	if err != nil {
		return nil, fmt.Errorf("getting device code: %w", err)
	}

	if code == nil {
		return nil, ErrInvalidUserCode
	}

	if time.Now().After(code.ExpiresAt) {
		return nil, ErrExpiredCode
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

func generateUserCode(length int) (string, error) {
	const charset = "BCDFGHJKLMNPQRSTVWXZ" // Excludes vowels and similar-looking characters

	if length < 4 || length%2 != 0 {
		return "", errors.New("invalid user code length")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	code := make([]byte, length)
	for i := 0; i < length; i++ {
		code[i] = charset[int(bytes[i])%len(charset)]
		if i == length/2 {
			code = append(code[:i], append([]byte{'-'}, code[i:]...)...)
		}
	}

	return string(code), nil
}

func normalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}
