// Package validation provides code validation utilities for OAuth2 device flow
package validation

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Validation settings based on RFC 8628 section 6.1
const (
	MinLength    = 8   // Minimum total length excluding separator
	MaxLength    = 8   // Maximum total length excluding separator
	MinGroupSize = 4   // Minimum characters per group
	MinEntropy   = 2.0 // Minimum required entropy bits per RFC 8628 section 6.1
)

// ValidCharset contains the RECOMMENDED characters (excluding similar-looking chars) from RFC 8628 section 6.1
const ValidCharset = "BCDFGHJKLMNPQRSTVWXZ" // RFC 8628: A-Z excluding vowels and similar characters

var (
	// Format validation regex - enforces exact format with valid charset
	charsetPattern = fmt.Sprintf("[%s]", ValidCharset)
	codeRegex      = regexp.MustCompile(fmt.Sprintf("^%s{%d}-%s{%d}$",
		charsetPattern, MinGroupSize, charsetPattern, MinGroupSize))
)

// ValidationError represents a code validation error with specific context
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid user code %q: %s", e.Code, e.Message)
}

// ValidateUserCode checks if a user code meets all RFC 8628 requirements in order:
// 1. Basic format validation (length, charset, structure)
// 2. Entropy validation (primary security requirement, section 6.1)
// 3. Additional security constraints (character distribution)
func ValidateUserCode(code string) error {
	// Normalize code for validation, preserving original for error messages
	originalCode := code
	code = strings.ToUpper(strings.TrimSpace(code))
	baseCode := strings.ReplaceAll(code, "-", "")

	// Step 1: Basic format validation
	if len(baseCode) != MinLength {
		return &ValidationError{
			Code:    originalCode,
			Message: fmt.Sprintf("code must be exactly %d characters (excluding separator)", MinLength),
		}
	}

	if !codeRegex.MatchString(code) {
		return &ValidationError{
			Code: originalCode,
			Message: fmt.Sprintf(
				"code must be in format XXXX-XXXX using only allowed characters: %s (per RFC 8628)",
				ValidCharset,
			),
		}
	}

	// Step 2: Entropy validation (RFC 8628 section 6.1 security requirement)
	entropy := calculateEntropy(baseCode)
	if entropy < MinEntropy {
		return &ValidationError{
			Code: originalCode,
			Message: fmt.Sprintf(
				"insufficient entropy: %.2f bits (minimum %.2f bits required by RFC 8628)",
				entropy, MinEntropy,
			),
		}
	}

	// Step 3: Character distribution constraints
	// RFC 8628 suggests limiting character repetition to maintain high entropy
	charCounts := make(map[rune]int)
	maxAllowed := 2 // Maximum character repetition while maintaining entropy
	for _, char := range baseCode {
		charCounts[char]++
		if charCounts[char] > maxAllowed {
			return &ValidationError{
				Code: originalCode,
				Message: fmt.Sprintf(
					"for security, character %c cannot appear more than %d times per code",
					char, maxAllowed,
				),
			}
		}
	}

	return nil
}

// calculateEntropy calculates the Shannon entropy of the code in bits per RFC 8628
// This measures the randomness/unpredictability of the code, which is critical for security
func calculateEntropy(code string) float64 {
	if code == "" {
		return 0
	}

	// Calculate character frequencies
	freqs := make(map[rune]int)
	for _, char := range code {
		freqs[char]++
	}

	// Calculate Shannon entropy
	length := float64(len(code))
	entropy := 0.0
	for _, count := range freqs {
		prob := float64(count) / length
		entropy -= prob * math.Log2(prob)
	}

	// Return actual bits of entropy
	return entropy
}

// NormalizeCode converts a user code to the canonical storage format
func NormalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// FormatCode converts a normalized code into the RFC 8628 display format (XXXX-XXXX)
func FormatCode(code string) string {
	if len(code) < MinLength {
		return code
	}
	mid := len(code) / 2
	return code[:mid] + "-" + code[mid:]
}
