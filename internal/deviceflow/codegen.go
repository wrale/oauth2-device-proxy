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
	charset := []rune(validation.ValidCharset)
	charsetLen := len(charset)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		var builder strings.Builder
		freqs := make(map[rune]int)
		success := true

		// Generate first group
		for i := 0; i < validation.MinGroupSize; i++ {
			// Find available characters
			var available []rune
			for _, c := range charset {
				if freqs[c] < 2 { // Max 2 occurrences per RFC 8628 section 6.1
					available = append(available, c)
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
			// Map random byte to available index
			idx := int(b[0]) % len(available)

			// Add selected character
			char := available[idx]
			builder.WriteRune(char)
			freqs[char]++
		}

		if !success {
			continue
		}

		// Add separator
		builder.WriteRune('-')

		// Generate second group
		for i := 0; i < validation.MinGroupSize; i++ {
			// Find available characters
			var available []rune
			for _, c := range charset {
				if freqs[c] < 2 { // Max 2 occurrences per RFC 8628 section 6.1
					available = append(available, c)
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

			// Add selected character
			char := available[idx]
			builder.WriteRune(char)
			freqs[char]++
		}

		if !success {
			continue
		}

		// Get final code and validate
		code := builder.String()
		if err := validation.ValidateUserCode(code); err == nil {
			return code, nil
		}
	}

	return "", fmt.Errorf("failed to generate valid code after %d attempts", maxAttempts)
}
