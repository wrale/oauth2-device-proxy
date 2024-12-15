// Package deviceflow implements OAuth2 device flow code generation per RFC 8628
package deviceflow

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jmdots/oauth2-device-proxy/internal/validation"
)

// generateSecureCode generates a cryptographically secure device code per RFC 8628 section 3.2.
// The code is generated as random bytes and hex encoded to ensure uniform distribution.
// For a 64-character output (required by tests), we need 32 bytes of random data.
func generateSecureCode(length int) (string, error) {
	// Each byte becomes 2 hex chars, so divide length by 2 to get bytes needed
	bytesNeeded := length / 2
	bytes := make([]byte, bytesNeeded)

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// selectRandomChar selects a random character from available set without modulo bias.
// This implements the guidance in RFC 8628 section 6.1 by ensuring an unbiased
// selection from the available character set. The algorithm rejects values that
// would create bias rather than using modulo directly.
func selectRandomChar(available []rune) (rune, error) {
	availLen := len(available)
	// Find largest multiple of availLen that fits in a byte
	maxNeeded := 256 - (256 % availLen)

	// Keep trying until we get an unbiased value
	for {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return 0, fmt.Errorf("generating random byte: %w", err)
		}

		// Reject values that would create modulo bias
		if int(b[0]) >= maxNeeded {
			continue
		}

		// Safe to use modulo - no bias possible
		idx := int(b[0]) % availLen
		return available[idx], nil
	}
}

// generateUserCode generates a user-friendly code per RFC 8628 section 6.1.
// The code follows the format XXXX-XXXX where X is from the valid character set.
// The code must meet minimum entropy requirements and avoid character repetition
// to maintain security while being user-friendly.
func generateUserCode() (string, error) {
	maxAttempts := 100 // Prevent infinite loops
	charset := []rune(validation.ValidCharset)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		var code strings.Builder
		freqs := make(map[rune]int)
		success := true

		// Generate first group (XXXX-)
		for i := 0; i < validation.MinGroupSize && success; i++ {
			// Find characters still available (max 2 uses per char)
			var available []rune
			for _, c := range charset {
				if freqs[c] < 2 { // Limit per RFC 8628 section 6.1
					available = append(available, c)
				}
			}

			if len(available) == 0 {
				success = false
				break
			}

			char, err := selectRandomChar(available)
			if err != nil {
				return "", fmt.Errorf("selecting random character: %w", err)
			}

			code.WriteRune(char)
			freqs[char]++
		}

		if !success {
			continue // Try again if first group failed
		}

		code.WriteRune('-') // Add separator

		// Generate second group (-XXXX)
		for i := 0; i < validation.MinGroupSize && success; i++ {
			var available []rune
			for _, c := range charset {
				if freqs[c] < 2 {
					available = append(available, c)
				}
			}

			if len(available) == 0 {
				success = false
				break
			}

			char, err := selectRandomChar(available)
			if err != nil {
				return "", fmt.Errorf("selecting random character: %w", err)
			}

			code.WriteRune(char)
			freqs[char]++
		}

		if !success {
			continue // Try again if second group failed
		}

		// Validate the complete code
		result := code.String()
		if err := validation.ValidateUserCode(result); err != nil {
			continue // Try again if validation fails
		}

		return result, nil
	}

	return "", fmt.Errorf("failed to generate valid code after %d attempts", maxAttempts)
}
