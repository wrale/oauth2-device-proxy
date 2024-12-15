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
	ErrorCodeUnsupportedGrant     = "unsupported_grant_type"
)

// Error descriptions defined by RFC 8628
const (
	// Section 3.1 error descriptions
	ErrorDescMissingClientID      = "The client_id parameter is REQUIRED"
	ErrorDescDuplicateParams      = "Parameters MUST NOT be included more than once"
	ErrorDescInvalidRequestFormat = "Invalid request format"

	// Section 3.4 error descriptions
	ErrorDescMissingGrantType  = "The grant_type parameter is REQUIRED"
	ErrorDescMissingDeviceCode = "The device_code parameter is REQUIRED"
	ErrorDescUnsupportedGrant  = "Only urn:ietf:params:oauth:grant-type:device_code is supported"

	// Section 3.5 error descriptions
	ErrorDescAuthorizationPending = "The authorization request is still pending"
	ErrorDescSlowDown             = "Polling interval must be increased by 5 seconds"
	ErrorDescAccessDenied         = "The user denied the authorization request"
	ErrorDescExpiredToken         = "The device_code has expired"
	ErrorDescInvalidDeviceCode    = "The device_code is invalid or malformed"

	// Section 6.1 error descriptions
	ErrorDescInvalidUserCode   = "Invalid user code format"
	ErrorDescRateLimitExceeded = "Too many verification attempts"
)

// DeviceFlowError represents a structured error response per RFC 8628
type DeviceFlowError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// Error implements the error interface
func (e *DeviceFlowError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// NewDeviceFlowError creates a new device flow error with description
func NewDeviceFlowError(code string, description string) *DeviceFlowError {
	return &DeviceFlowError{
		Code:        code,
		Description: description,
	}
}

// Common errors that occur during the device authorization flow
var (
	// Auth flow errors per RFC 8628 section 3.5
	ErrInvalidDeviceCode    = NewDeviceFlowError(ErrorCodeInvalidGrant, ErrorDescInvalidDeviceCode)
	ErrExpiredCode          = NewDeviceFlowError(ErrorCodeExpiredToken, ErrorDescExpiredToken)
	ErrPendingAuthorization = NewDeviceFlowError(ErrorCodeAuthorizationPending, ErrorDescAuthorizationPending)
	ErrSlowDown             = NewDeviceFlowError(ErrorCodeSlowDown, ErrorDescSlowDown)
	ErrAccessDenied         = NewDeviceFlowError(ErrorCodeAccessDenied, ErrorDescAccessDenied)

	// Request validation errors per RFC 8628 section 3.1
	ErrMissingClientID = NewDeviceFlowError(ErrorCodeInvalidRequest, ErrorDescMissingClientID)
	ErrDuplicateParams = NewDeviceFlowError(ErrorCodeInvalidRequest, ErrorDescDuplicateParams)
	ErrInvalidRequest  = NewDeviceFlowError(ErrorCodeInvalidRequest, ErrorDescInvalidRequestFormat)

	// Grant type errors per RFC 8628 section 3.4
	ErrMissingGrantType  = NewDeviceFlowError(ErrorCodeInvalidRequest, ErrorDescMissingGrantType)
	ErrMissingDeviceCode = NewDeviceFlowError(ErrorCodeInvalidRequest, ErrorDescMissingDeviceCode)
	ErrUnsupportedGrant  = NewDeviceFlowError(ErrorCodeUnsupportedGrant, ErrorDescUnsupportedGrant)

	// Input validation errors
	ErrInvalidUserCode   = NewDeviceFlowError(ErrorCodeInvalidRequest, ErrorDescInvalidUserCode)
	ErrRateLimitExceeded = NewDeviceFlowError(ErrorCodeSlowDown, ErrorDescRateLimitExceeded)
)

// AsDeviceFlowError attempts to convert an error to a DeviceFlowError
func AsDeviceFlowError(err error) (*DeviceFlowError, bool) {
	var dfe *DeviceFlowError
	if errors.As(err, &dfe) {
		return dfe, true
	}
	return nil, false
}
