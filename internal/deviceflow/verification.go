// Package deviceflow implements verification for OAuth 2.0 Device Flow
package deviceflow

import (
	"context"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// VerifyUserCode verifies a user code and checks rate limiting.
// Error order follows RFC 8628 section 3.5:
// 1. Server errors (precedence over all others)
// 2. Invalid/malformed code
// 3. Expired code
// 4. Rate limiting
func (f *flowImpl) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	// Run format validation first
	if err := validation.ValidateUserCode(userCode); err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidGrant,
			"The device_code is invalid or malformed",
		)
	}

	// Normalize for lookup
	normalized := validation.NormalizeCode(userCode)

	// Check store errors first per RFC 8628
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		// All store errors are server errors per RFC 8628
		return nil, NewDeviceFlowError(
			ErrorCodeServerError,
			"Internal server error",
		)
	}

	// Check code existence next
	if code == nil {
		return nil, NewDeviceFlowError(
			ErrorCodeInvalidGrant,
			"The device_code is invalid or malformed",
		)
	}

	// Check expiration third
	if time.Now().After(code.ExpiresAt) {
		return nil, NewDeviceFlowError(
			ErrorCodeExpiredToken,
			"The device_code has expired",
		)
	}

	// Finally check rate limiting per RFC 8628 section 5.2
	pollCount, err := f.store.GetPollCount(ctx, code.DeviceCode, f.rateLimitWindow)
	if err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeServerError,
			"Internal server error",
		)
	}

	if pollCount >= f.maxPollsPerMin {
		return nil, NewDeviceFlowError(
			ErrorCodeSlowDown,
			"Polling too frequently",
		)
	}

	// Update poll count to enforce proper rate limiting
	if err := f.store.IncrementPollCount(ctx, code.DeviceCode); err != nil {
		return nil, NewDeviceFlowError(
			ErrorCodeServerError,
			"Internal server error",
		)
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	code.ExpiresIn = int(remaining)

	return code, nil
}
