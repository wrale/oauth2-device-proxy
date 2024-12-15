// Package deviceflow implements token handling for OAuth 2.0 Device Flow
package deviceflow

import (
	"context"
	"fmt"
	"time"
)

// CheckDeviceCode checks device code status per RFC 8628 section 3.4
// It implements the device access token request and response flow with proper
// rate limiting and error handling per sections 3.4 and 3.5
func (f *Flow) CheckDeviceCode(ctx context.Context, deviceCode string) (*TokenResponse, error) {
	// Use GetDeviceCode for consistent validation
	code, err := f.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("validating device code: %w", err)
	}

	// Check rate limiting per RFC 8628 section 3.5
	if !f.canPoll(code.LastPoll) {
		return nil, ErrSlowDown
	}

	// Update last poll time
	code.LastPoll = time.Now()
	code.ExpiresIn = int(time.Until(code.ExpiresAt).Seconds())
	if err := f.store.SaveDeviceCode(ctx, code); err != nil {
		return nil, fmt.Errorf("updating last poll time: %w", err)
	}

	// Check if token exists
	token, err := f.store.GetToken(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("getting token: %w", err)
	}

	if token == nil {
		return nil, ErrPendingAuthorization
	}

	return token, nil
}

// CompleteAuthorization completes device authorization by saving the token.
// This should be called after the user has approved the authorization request
// and a token has been obtained from the authorization server.
func (f *Flow) CompleteAuthorization(ctx context.Context, deviceCode string, token *TokenResponse) error {
	// Use GetDeviceCode for consistent validation
	code, err := f.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		return err
	}

	// Save the token
	if err := f.store.SaveToken(ctx, deviceCode, token); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}

	return nil
}

// canPoll determines if polling is allowed based on the interval per RFC 8628.
// This implements the "slow_down" error condition by enforcing minimum polling intervals.
func (f *Flow) canPoll(lastPoll time.Time) bool {
	return time.Since(lastPoll) >= f.pollInterval
}
