// Package deviceflow implements OAuth 2.0 Device Authorization Grant (RFC 8628)
package deviceflow

import (
	"time"
)

// Option configures the device flow implementation
type Option func(*flowImpl)

// WithExpiryDuration sets the code expiry duration
// per RFC 8628 section 3.2, expires_in must be greater than min duration
func WithExpiryDuration(d time.Duration) Option {
	return func(f *flowImpl) {
		f.expiryDuration = d
	}
}

// WithPollInterval sets the minimum polling interval
// per RFC 8628 section 3.5, clients must wait between polling attempts
func WithPollInterval(d time.Duration) Option {
	return func(f *flowImpl) {
		f.pollInterval = d
	}
}

// WithUserCodeLength sets the user code length
// length must be compatible with RFC 8628 section 6.1 requirements
func WithUserCodeLength(length int) Option {
	return func(f *flowImpl) {
		f.userCodeLength = length
	}
}

// WithRateLimit sets rate limiting parameters for token polling
// per RFC 8628 section 3.5, servers should enforce rate limits
func WithRateLimit(window time.Duration, maxPolls int) Option {
	return func(f *flowImpl) {
		f.rateLimitWindow = window
		f.maxPollsPerMin = maxPolls
	}
}
