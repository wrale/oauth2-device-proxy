// Package deviceflow implements OAuth 2.0 Device Authorization Grant per RFC 8628
package deviceflow

import (
	"errors"
	"fmt"
)

// Error codes defined by RFC 8628 section 3.5
const (
	ErrorCodeAuthorizationPending = "authorization_pending"
	ErrorCodeSlowDown             = "slow_down"
	ErrorCodeAccessDenied         = "access_denied"
	ErrorCodeExpiredToken         = "expired_token"
	ErrorCodeInvalidGrant         = "invalid_grant"
	ErrorCodeInvalidRequest       = "invalid_request"
)

// Common errors that may occur during the device authorization flow
var (
	// ErrInvalidDeviceCode indicates a missing or malformed device code
	ErrInvalidDeviceCode = errors.New(ErrorCodeInvalidGrant)

	// ErrInvalidUserCode indicates an invalid or expired user code
	ErrInvalidUserCode = errors.New(ErrorCodeInvalidRequest)

	// ErrPendingAuthorization indicates user authorization is not yet complete
	ErrPendingAuthorization = errors.New(ErrorCodeAuthorizationPending)

	// ErrSlowDown indicates polling rate limit exceeded per RFC 8628
	ErrSlowDown = errors.New(ErrorCodeSlowDown)

	// ErrExpiredCode indicates the device or user code has expired
	ErrExpiredCode = errors.New(ErrorCodeExpiredToken)

	// ErrAccessDenied indicates the user denied the authorization request
	ErrAccessDenied = errors.New(ErrorCodeAccessDenied)

	// ErrRateLimitExceeded indicates too many verification attempts
	ErrRateLimitExceeded = errors.New("verification attempts exceeded")
)

// DeviceFlowError represents a structured error response per RFC 8628
type DeviceFlowError struct {
	Code        string
	Description string
}

// Error implements the error interface
func (e *DeviceFlowError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// NewDeviceFlowError creates a new device flow error with description
func NewDeviceFlowError(code string, description string) *DeviceFlowError {
	return &DeviceFlowError{
		Code:        code,
		Description: description,
	}
}
