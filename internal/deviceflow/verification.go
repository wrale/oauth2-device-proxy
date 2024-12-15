// Package deviceflow implements verification for OAuth 2.0 Device Flow
package deviceflow

import (
	"context"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// VerifyUserCode verifies a user code and checks rate limiting.
// Error checking follows exact order specified in RFC 8628 section 3.5:
// 1. Input validation (format, charset, entropy)
// 2. Store error checking
// 3. Code existence
// 4. Code expiration
// 5. Rate limiting
func (f *Flow) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	// First validate format per RFC 8628 section 6.1
	if err := validation.ValidateUserCode(userCode); err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Invalid user code format: must use BCDFGHJKLMNPQRSTVWXZ charset",
		)
	}

	// Normalize code for consistent handling
	normalized := validation.NormalizeCode(userCode)

	// Check store errors first per RFC 8628
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		// Wrap store errors for proper error response format
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Error validating code: internal error",
		)
	}

	// Code not found after validation
	if code == nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Invalid user code: code not found",
		)
	}

	// Check expiration before rate limiting
	if time.Now().After(code.ExpiresAt) {
		return nil, NewDeviceFlowError(
			ErrorCodeExpiredToken,
			"Code has expired",
		)
	}

	// Check rate limiting per RFC 8628 section 5.2
	allowed, err := f.store.CheckDeviceCodeAttempts(ctx, code.DeviceCode)
	if err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Error checking rate limit: internal error",
		)
	}
	if !allowed {
		return nil, NewDeviceFlowError(
			ErrorCodeSlowDown,
			"Too many verification attempts, please wait",
		)
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	code.ExpiresIn = int(remaining)

	return code, nil
}
