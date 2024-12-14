// Package validation provides code validation utilities for OAuth2 device flow
package validation

import (
	"fmt"
	"math/bits"
	"regexp"
	"strings"
)

// Validation settings
const (
	MinLength    = 8  // Minimum total length excluding separator
	MaxLength    = 12 // Maximum total length excluding separator
	MinGroupSize = 4  // Minimum characters per group
	MinEntropy   = 20 // Minimum required entropy bits
)

// ValidCharset contains the allowed characters for user codes
const ValidCharset = "BCDFGHJKLMNPQRSTVWXZ" // Excludes vowels and similar-looking characters

var (
	// Format validation regex
	codeRegex = regexp.MustCompile(fmt.Sprintf("^[%s]{%d,}-[%s]{%d,}$",
		ValidCharset, MinGroupSize, ValidCharset, MinGroupSize))
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

	// Check basic format
	if !codeRegex.MatchString(code) {
		return &ValidationError{
			Code:    code,
			Message: "code must be in format XXXX-XXXX using only allowed characters",
		}
	}

	// Check length without separator
	baseCode := strings.ReplaceAll(code, "-", "")
	if len(baseCode) < MinLength || len(baseCode) > MaxLength {
		return &ValidationError{
			Code:    code,
			Message: fmt.Sprintf("code length must be between %d and %d characters", MinLength, MaxLength),
		}
	}

	// Check entropy
	if entropy := calculateEntropy(baseCode); entropy < MinEntropy {
		return &ValidationError{
			Code:    code,
			Message: fmt.Sprintf("code entropy %f bits is below required minimum %d bits", entropy, MinEntropy),
		}
	}

	// Check character distribution
	charCounts := make(map[rune]int)
	for _, char := range baseCode {
		charCounts[char]++
		if charCounts[char] > len(baseCode)/2 {
			return &ValidationError{
				Code:    code,
				Message: "code contains too many repeated characters",
			}
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

	// Calculate entropy
	length := float64(len(code))
	entropy := 0.0
	for _, count := range freqs {
		prob := float64(count) / length
		entropy -= prob * float64(bits.TrailingZeros64(uint64(prob)))
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
