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
	maxAllowed := 2    // Maximum times a character can appear per RFC 8628

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// First half + hyphen + second half (8 characters total)
		code := make([]byte, validation.MinGroupSize*2+1)
		freqs := make(map[byte]int)
		valid := true

		// Fill first half (4 chars)
		for i := 0; i < validation.MinGroupSize && valid; i++ {
			char, err := selectChar([]byte(validation.ValidCharset), freqs, maxAllowed)
			if err != nil {
				valid = false
				break
			}
			code[i] = char
		}

		// Add hyphen separator
		if valid {
			code[validation.MinGroupSize] = '-'

			// Fill second half (4 more chars)
			for i := 0; i < validation.MinGroupSize && valid; i++ {
				char, err := selectChar([]byte(validation.ValidCharset), freqs, maxAllowed)
				if err != nil {
					valid = false
					break
				}
				code[validation.MinGroupSize+1+i] = char
			}
		}

		// Validate the generated code
		if valid {
			generated := string(code)
			if err := validation.ValidateUserCode(generated); err == nil {
				return generated, nil
			}
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
