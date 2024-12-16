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
// 2. Code validation and lookup
// 3. Code expiration check
// 4. Rate limiting check
func (f *flowImpl) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	// Run format validation first to catch obvious issues
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
		return nil, NewDeviceFlowError(
			ErrorCodeServerError,
			"Error validating code: internal error",
		)
	}

	// Check code existence next
	if code == nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidRequest,
			"Invalid user code: code not found",
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
			ErrorCodeServerError,
			"Error validating code: internal error",
		)
	}

	if pollCount >= f.maxPollsPerMin {
		return nil, NewDeviceFlowError(
			ErrorCodeSlowDown,
			"Too many verification attempts, please wait",
		)
	}

	// Update poll count even for verification attempts to enforce proper rate limiting
	if err := f.store.IncrementPollCount(ctx, code.DeviceCode); err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeServerError,
			"Error validating code: internal error",
		)
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	code.ExpiresIn = int(remaining)

	return code, nil
}
