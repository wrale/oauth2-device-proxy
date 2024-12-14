// Package validation provides code validation utilities for OAuth2 device flow
package validation

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Validation settings
const (
	MinLength    = 8  // Minimum total length excluding separator
	MaxLength    = 12 // Maximum total length excluding separator
	MinGroupSize = 4  // Minimum characters per group
	MinEntropy   = 2  // Minimum required entropy bits
)

// ValidCharset contains the allowed characters for user codes
const ValidCharset = "BCDFGHJKLMNPQRSTVWXZ" // Excludes vowels and similar-looking characters

var (
	// Format validation regex - enforces exact format with valid charset
	charsetPattern = fmt.Sprintf("[%s]", ValidCharset)
	codeRegex      = regexp.MustCompile(fmt.Sprintf("^%s{%d}-%s{%d}$",
		charsetPattern, MinGroupSize, charsetPattern, MinGroupSize))
)

// ValidationError represents a code validation error
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid user code %q: %s", e.Code, e.Message)
}

// ValidateUserCode checks if a user code meets all requirements
func ValidateUserCode(code string) error {
	// Normalize code
	code = strings.ToUpper(strings.TrimSpace(code))

	// First check length without separator to give most specific error
	baseCode := strings.ReplaceAll(code, "-", "")
	if len(baseCode) < MinLength {
		return &ValidationError{
			Code:    code,
			Message: fmt.Sprintf("length must be between %d and %d characters", MinLength, MaxLength),
		}
	}
	if len(baseCode) > MaxLength {
		return &ValidationError{
			Code:    code,
			Message: fmt.Sprintf("length must be between %d and %d characters", MinLength, MaxLength),
		}
	}

	// Check format and allowed characters
	if !codeRegex.MatchString(code) {
		return &ValidationError{
			Code:    code,
			Message: "code must be in format XXXX-XXXX using only allowed characters",
		}
	}

	// Check character distribution before entropy
	charCounts := make(map[rune]int)
	maxAllowedRepeats := (len(baseCode) / 2) + 1 // Allow up to half rounded up
	for _, char := range baseCode {
		charCounts[char]++
		if charCounts[char] > maxAllowedRepeats {
			return &ValidationError{
				Code:    code,
				Message: "too many repeated characters",
			}
		}
	}

	// Check entropy last since it's most expensive
	if entropy := calculateEntropy(baseCode); entropy < MinEntropy {
		return &ValidationError{
			Code:    code,
			Message: fmt.Sprintf("code entropy %.2f bits is below required minimum %d bits", entropy, MinEntropy),
		}
	}

	return nil
}

// calculateEntropy calculates the Shannon entropy of the code in bits
func calculateEntropy(code string) float64 {
	if code == "" {
		return 0
	}

	// Count character frequencies
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

	return entropy
}

// NormalizeCode converts a user code to canonical format
func NormalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// FormatCode converts a normalized code back to display format
func FormatCode(code string) string {
	if len(code) < MinLength {
		return code
	}
	mid := len(code) / 2
	return code[:mid] + "-" + code[mid:]
}
