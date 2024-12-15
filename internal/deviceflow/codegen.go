// Package deviceflow implements OAuth2 device flow code generation
package deviceflow

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

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
		// Generate each half of the code separately
		var parts [2]string
		freqs := make(map[byte]int)

		for half := 0; half < 2; half++ {
			var chars []byte
			for i := 0; i < validation.MinGroupSize; i++ {
				char, err := selectChar([]byte(validation.ValidCharset), freqs, 2)
				if err != nil {
					break // Invalid character distribution, try again
				}
				chars = append(chars, char)
			}
			if len(chars) != validation.MinGroupSize {
				continue // Retry if invalid length
			}
			parts[half] = string(chars)
		}

		// Join with hyphen
		code := fmt.Sprintf("%s-%s", parts[0], parts[1])

		// Validate final code meets all requirements
		if err := validation.ValidateUserCode(code); err == nil {
			return code, nil
		}
	}

	return "", fmt.Errorf("failed to generate valid code after %d attempts", maxAttempts)
}

// selectChar chooses a random available character that hasn't exceeded maxAllowed frequency
func selectChar(charset []byte, freqs map[byte]int, maxAllowed int) (byte, error) {
	// Create list of available characters that haven't hit max frequency
	available := make([]byte, 0, len(charset))
	for _, c := range charset {
		if freqs[c] < maxAllowed {
			available = append(available, c)
		}
	}

	if len(available) == 0 {
		return 0, fmt.Errorf("no characters available under frequency limit %d", maxAllowed)
	}

	// Generate random index
	randByte := make([]byte, 1)
	if _, err := rand.Read(randByte); err != nil {
		return 0, err
	}

	// Select and track character
	selected := available[int(randByte[0])%len(available)]
	freqs[selected]++

	return selected, nil
}
