package deviceflow

import (
	"time"

	"github.com/jmdots/oauth2-device-proxy/internal/validation"
)

// Option configures the device flow
type Option func(*Flow)

// WithExpiryDuration sets the code expiry duration
// per RFC 8628 section 3.2, expires_in must be greater than min duration
func WithExpiryDuration(d time.Duration) Option {
	return func(f *Flow) {
		f.expiryDuration = d
	}
}

// WithPollInterval sets the minimum polling interval
// per RFC 8628 section 3.5, clients must wait between polling attempts
func WithPollInterval(d time.Duration) Option {
	return func(f *Flow) {
		f.pollInterval = d
	}
}

// WithUserCodeLength sets the user code length
// length must be compatible with RFC 8628 section 6.1 requirements
func WithUserCodeLength(length int) Option {
	return func(f *Flow) {
		f.userCodeLength = length
	}
}

// WithRateLimit sets rate limiting parameters for token polling
// per RFC 8628 section 3.5, servers should enforce rate limits
func WithRateLimit(window time.Duration, maxPolls int) Option {
	return func(f *Flow) {
		f.rateLimitWindow = window
		f.maxPollsPerMin = maxPolls
	}
}

// newDefaultFlow creates a Flow with default settings
func newDefaultFlow(store Store, baseURL string) *Flow {
	return &Flow{
		store:           store,
		baseURL:         baseURL,
		expiryDuration:  15 * time.Minute,     // RFC 8628 recommended expiry
		pollInterval:    5 * time.Second,      // RFC 8628 recommended interval
		userCodeLength:  validation.MinLength, // RFC 8628 section 6.1
		rateLimitWindow: time.Minute,          // Rate limit window
		maxPollsPerMin:  12,                   // Max polls per minute
	}
}
