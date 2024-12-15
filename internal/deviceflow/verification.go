// Package deviceflow implements verification for OAuth 2.0 Device Flow
package deviceflow

import (
	"context"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// VerifyUserCode verifies a user code and checks rate limiting.
// Error checking follows exact RFC 8628 section 3.5 order:
// 1. Store errors take precedence (authorization server errors)
// 2. Code existence and state (authorization pending, expired)
// 3. Rate limiting (slow_down)
// 4. Code format validation
func (f *Flow) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	// Normalize for lookup - validation comes later
	normalized := validation.NormalizeCode(userCode)

	// First check store errors - these take precedence per RFC 8628
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Error validating code: internal error",
		)
	}

	// Code existence check next
	if code == nil {
		// For non-existent codes, provide validation feedback
		if err := validation.ValidateUserCode(userCode); err != nil {
			return nil, NewDeviceFlowError(
				ErrorCodeInvalidRequest,
				"Invalid user code format: must use BCDFGHJKLMNPQRSTVWXZ charset",
			)
		}
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Invalid user code: code not found",
		)
	}

	// Next check expiration
	if time.Now().After(code.ExpiresAt) {
		return nil, NewDeviceFlowError(
			ErrorCodeExpiredToken,
			"Code has expired",
		)
	}

	// Rate limiting check per RFC 8628 section 5.2
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

	// For valid codes, run format validation last to catch any issues
	if err := validation.ValidateUserCode(userCode); err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Invalid user code format: must use BCDFGHJKLMNPQRSTVWXZ charset",
		)
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	code.ExpiresIn = int(remaining)

	return code, nil
}
