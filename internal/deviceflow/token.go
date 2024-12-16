// Package deviceflow implements token handling for OAuth 2.0 Device Flow
package deviceflow

import "time"

// canPoll determines if polling is allowed based on the interval per RFC 8628.
// This implements the "slow_down" error condition by enforcing minimum polling intervals.
func (f *flowImpl) canPoll(lastPoll time.Time) bool {
	return time.Since(lastPoll) >= f.pollInterval
}
