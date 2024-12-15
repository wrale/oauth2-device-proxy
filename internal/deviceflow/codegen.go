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

// selectRandomChar selects a random character from available set without modulo bias
func selectRandomChar(available []rune) (rune, error) {
	availLen := len(available)
	// Calculate required bytes for random selection per RFC 8628 section 6.1
	maxNeeded := 256 - (256 % availLen)

	for {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return 0, fmt.Errorf("generating random byte: %w", err)
		}

		// Reject values that would cause modulo bias
		if int(b[0]) >= maxNeeded {
			continue
		}

		// Safe to use modulo here - no bias
		idx := int(b[0]) % availLen
		return available[idx], nil
	}
}

// generateUserCode generates a user-friendly code per RFC 8628 section 6.1
func generateUserCode() (string, error) {
	maxAttempts := 100 // Prevent infinite loops
	charset := []rune(validation.ValidCharset)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		var codeBuilder strings.Builder
		freqs := make(map[rune]int)
		success := true

		// Generate first group of characters
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

			char, err := selectRandomChar(available)
			if err != nil {
				return "", fmt.Errorf("selecting random character: %w", err)
			}

			codeBuilder.WriteRune(char)
			freqs[char]++
		}

		if !success {
			continue
		}

		// Add separator
		codeBuilder.WriteRune('-')

		// Generate second group of characters
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

			char, err := selectRandomChar(available)
			if err != nil {
				return "", fmt.Errorf("selecting random character: %w", err)
			}

			codeBuilder.WriteRune(char)
			freqs[char]++
		}

		if !success {
			continue
		}

		// Validate the generated code before returning
		code := codeBuilder.String()
		if err := validation.ValidateUserCode(code); err != nil {
			continue // Try again if validation fails
		}

		// RFC 8628 Section 6.1 validation all passed
		return code, nil
	}

	return "", fmt.Errorf("failed to generate valid code after %d attempts", maxAttempts)
}
