// Package deviceflow implements OAuth2 device flow code generation
package deviceflow

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/jmdots/oauth2-device-proxy/internal/validation"
)

// generateSecureCode generates a cryptographically secure random code of specified length
func generateSecureCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// generateUserCode generates a user-friendly code per RFC 8628 section 6.1
func generateUserCode() (string, error) {
	maxAttempts := 100 // Prevent infinite loops

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Create a string builder for each half
		var parts [2]string
		freqs := make(map[rune]int)
		success := true

		for half := 0; half < 2; half++ {
			chars := make([]byte, validation.MinGroupSize)

			// Generate each character ensuring max frequency not exceeded
			for i := 0; i < validation.MinGroupSize; i++ {
				// Find available characters
				var available []byte
				for _, c := range validation.ValidCharset {
					if freqs[c] < 2 { // Max 2 occurrences per RFC 8628 section 6.1
						available = append(available, byte(c))
					}
				}

				if len(available) == 0 {
					success = false
					break
				}

				// Generate random index
				b := make([]byte, 1)
				if _, err := rand.Read(b); err != nil {
					return "", fmt.Errorf("generating random byte: %w", err)
				}
				idx := int(b[0]) % len(available)

				// Select and track character
				chars[i] = available[idx]
				freqs[rune(available[idx])]++
			}

			if !success {
				break
			}
			parts[half] = string(chars)
		}

		if !success {
			continue // Try again if character distribution failed
		}

		// Join with hyphen
		code := fmt.Sprintf("%s-%s", parts[0], parts[1])

		// Validate meets all RFC 8628 requirements
		if err := validation.ValidateUserCode(code); err == nil {
			return code, nil
		}
	}

	return "", fmt.Errorf("failed to generate valid code after %d attempts", maxAttempts)
}
