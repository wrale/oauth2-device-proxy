package deviceflow

import "errors"

// Common errors that may occur during the device authorization flow
var (
	// ErrInvalidDeviceCode indicates a missing or invalid device code
	ErrInvalidDeviceCode = errors.New("invalid device code")

	// ErrInvalidUserCode indicates an invalid or expired user code
	ErrInvalidUserCode = errors.New("invalid user code")

	// ErrPendingAuthorization indicates user authorization is not yet complete
	ErrPendingAuthorization = errors.New("authorization pending")

	// ErrSlowDown indicates polling rate limit exceeded per RFC 8628
	ErrSlowDown = errors.New("polling too frequently")

	// ErrExpiredCode indicates the device or user code has expired
	ErrExpiredCode = errors.New("code expired")

	// ErrRateLimitExceeded indicates too many verification attempts
	ErrRateLimitExceeded = errors.New("verification attempts exceeded, per RFC 8628 section 5.2")
)
