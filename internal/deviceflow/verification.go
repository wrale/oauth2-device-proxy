// Package deviceflow implements verification for OAuth 2.0 Device Flow
package deviceflow

import (
	"context"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// VerifyUserCode verifies a user code and checks rate limiting.
// Error handling follows RFC 8628 section 3.3 for user interaction:
// 1. Input validation errors (user code format)
// 2. Store errors (server issues)
// 3. Code state (expired, not found)
// 4. Rate limiting
func (f *flowImpl) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	// Run format validation first
	if err := validation.ValidateUserCode(userCode); err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Invalid user code format: must use BCDFGHJKLMNPQRSTVWXZ charset",
		)
	}

	// Normalize for lookup
	normalized := validation.NormalizeCode(userCode)

	// Check store errors first per RFC 8628
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		// Store errors are validation errors in verification context
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Error validating code: internal error",
		)
	}

	// Check code existence next
	if code == nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidGrant,
			"The user code was not found",
		)
	}

	// Check expiration third
	if time.Now().After(code.ExpiresAt) {
		return nil, NewDeviceFlowError(
			ErrorCodeExpiredToken,
			"Code has expired",
		)
	}

	// Finally check rate limiting per RFC 8628 section 5.2
	pollCount, err := f.store.GetPollCount(ctx, code.DeviceCode, f.rateLimitWindow)
	if err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Error validating code: internal error",
		)
	}

	if pollCount >= f.maxPollsPerMin {
		return nil, NewDeviceFlowError(
			ErrorCodeSlowDown,
			"Too many verification attempts, please wait",
		)
	}

	// Update poll count to enforce proper rate limiting
	if err := f.store.IncrementPollCount(ctx, code.DeviceCode); err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Error validating code: internal error",
		)
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	code.ExpiresIn = int(remaining)

	return code, nil
}
