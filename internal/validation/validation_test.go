// Package validation provides code validation utilities for OAuth2 device flow
package validation

import (
	"strings"
	"testing"
)

// TestValidateUserCode verifies the code validation rules in order of precedence:
// 1. Basic format (length, charset, structure)
// 2. Entropy requirements (fundamental security property)
// 3. Repeated character limits (additional security constraint)
func TestValidateUserCode(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid code",
			code:    "BCDH-KLMN",
			wantErr: false,
		},
		{
			name:    "invalid characters",
			code:    "ABCD-EFGH", // Contains vowels
			wantErr: true,
			errMsg:  "using only allowed characters",
		},
		{
			name:    "too short",
			code:    "BCD-KLM",
			wantErr: true,
			errMsg:  "length must be exactly 8 characters",
		},
		{
			name:    "too long",
			code:    "BCDHJK-LMNPQR",
			wantErr: true,
			errMsg:  "length must be exactly 8 characters",
		},
		{
			name:    "missing separator",
			code:    "BCDHKLMN",
			wantErr: true,
			errMsg:  "must be in format",
		},
		{
			name:    "invalid separator position",
			code:    "BCD-HKLMN",
			wantErr: true,
			errMsg:  "must be in format",
		},
		{
			name:    "low entropy - repeating pairs",
			code:    "BBBB-CCCC",
			wantErr: true,
			errMsg:  "entropy", // Primary validation failure is entropy
		},
		{
			name:    "low entropy - alternating pattern",
			code:    "BCBC-BCBC",
			wantErr: true,
			errMsg:  "entropy",
		},
		{
			name:    "repeated chars with sufficient entropy",
			code:    "BBBK-LMNN", // Good entropy but too many B's
			wantErr: true,
			errMsg:  "too many repeated characters",
		},
		{
			name:    "with whitespace",
			code:    " BCDH-KLMN ",
			wantErr: false,
		},
		{
			name:    "mixed case",
			code:    "bcdh-klmn",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserCode(tt.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUserCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateUserCode() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		minValue float64
	}{
		{
			name:     "empty string",
			code:     "",
			minValue: 0,
		},
		{
			name:     "single character",
			code:     "B",
			minValue: 0,
		},
		{
			name:     "two different characters",
			code:     "BC",
			minValue: 1.0,
		},
		{
			name:     "repeating pattern",
			code:     "BCBCBC",
			minValue: 1.0,
		},
		{
			name:     "all different characters",
			code:     "BCDFGHJK",
			minValue: 2.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateEntropy(tt.code)
			if got < tt.minValue {
				t.Errorf("calculateEntropy() = %v, want >= %v", got, tt.minValue)
			}
		})
	}
}

func TestNormalizeCode(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "already normalized",
			code: "BCDHKLMN",
			want: "BCDHKLMN",
		},
		{
			name: "with separator",
			code: "BCDH-KLMN",
			want: "BCDHKLMN",
		},
		{
			name: "with whitespace",
			code: " BCDH-KLMN ",
			want: "BCDHKLMN",
		},
		{
			name: "mixed case",
			code: "bcdh-klmn",
			want: "BCDHKLMN",
		},
		{
			name: "multiple separators",
			code: "BC-DH-KL-MN",
			want: "BCDHKLMN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeCode(tt.code); got != tt.want {
				t.Errorf("NormalizeCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCode(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "eight characters",
			code: "BCDHKLMN",
			want: "BCDH-KLMN",
		},
		{
			name: "ten characters",
			code: "BCDHKLMNPQ",
			want: "BCDHK-LMNPQ",
		},
		{
			name: "too short",
			code: "BCD",
			want: "BCD",
		},
		{
			name: "odd length",
			code: "BCDHKLMNP",
			want: "BCDH-KLMNP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatCode(tt.code); got != tt.want {
				t.Errorf("FormatCode() = %v, want %v", got, tt.want)
			}
		})
	}
}
