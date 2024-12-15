// Package deviceflow implements verification for OAuth 2.0 Device Flow
package deviceflow

import (
	"context"
	"fmt"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// VerifyUserCode verifies a user code and checks rate limiting.
// Error checking order per RFC 8628:
// 1. Store errors take precedence
// 2. Check if code exists
// 3. Check expiration
// 4. Check rate limiting
// 5. Validate code format
func (f *Flow) VerifyUserCode(ctx context.Context, userCode string) (*DeviceCode, error) {
	normalized := validation.NormalizeCode(userCode)

	// First check store errors - these take precedence
	code, err := f.store.GetDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		return nil, err // Storage errors pass through unchanged
	}

	// Code not found - validate format for helpful error
	if code == nil {
		if err := validation.ValidateUserCode(userCode); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidUserCode, err)
		}
		return nil, ErrInvalidUserCode
	}

	// Code exists - check expiration first
	if time.Now().After(code.ExpiresAt) {
		return nil, ErrExpiredCode
	}

	// Check rate limiting per RFC 8628 section 5.2
	allowed, err := f.store.CheckDeviceCodeAttempts(ctx, code.DeviceCode)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrRateLimitExceeded
	}

	// Update ExpiresIn based on remaining time
	remaining := time.Until(code.ExpiresAt).Seconds()
	code.ExpiresIn = int(remaining)

	return code, nil
}
