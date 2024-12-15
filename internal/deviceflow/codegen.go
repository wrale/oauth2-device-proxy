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
	// Convert length to bytes needed for hex encoding
	bytes := make([]byte, (length+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return hex.EncodeToString(bytes)[:length], nil
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
	maxAttempts := 100
	charset := []rune(validation.ValidCharset)

	// Continue attempting until we get a valid code
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var code strings.Builder
		freqs := make(map[rune]int)

		// Generate first group of characters
		success := true
		for i := 0; i < validation.MinGroupSize && success; i++ {
			var available []rune
			for _, c := range charset {
				if freqs[c] < 2 { // Limit character frequency per RFC 8628
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
			continue // Try again if generation failed
		}

		code.WriteRune('-') // Add separator

		// Generate second group of characters
		for i := 0; i < validation.MinGroupSize && success; i++ {
			var available []rune
			for _, c := range charset {
				if freqs[c] < 2 { // Limit character frequency per RFC 8628
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
			continue // Try again if generation failed
		}

		// Validate generated code against all RFC 8628 section 6.1 requirements
		result := code.String()
		if err := validation.ValidateUserCode(result); err != nil {
			continue // Try again if validation fails
		}

		return result, nil
	}

	return "", fmt.Errorf("failed to generate valid code after %d attempts", maxAttempts)
}
