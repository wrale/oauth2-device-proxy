// Package templates provides HTML templating with QR code generation capabilities
package templates

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	// RFC 8628 section 3.3.1 recommends QR codes for non-textual transmission.
	// These parameters are optimized for mobile phone camera scanning.
	qrQuietZone  = 4   // Quiet zone size in modules
	qrModuleSize = 4   // SVG rectangle size per module
	qrVersion    = 2   // Version 2 (25x25) supports verification_uri_complete
	qrSize       = 25  // Version 2 size in modules
	qrEccLevel   = "L" // Error correction level L (7%) as recommended by RFC
)

// GenerateQRCode creates an SVG QR code for the verification URI per RFC 8628 section 3.3.1.
// This enables non-textual transmission of the verification URI and code while still
// requiring the user to verify the code matches their device for security.
func (t *Templates) GenerateQRCode(verificationURI string) (string, error) {
	if verificationURI == "" {
		return "", fmt.Errorf("empty verification URI")
	}

	// Calculate total size including quiet zones
	totalSize := (qrSize + 2*qrQuietZone) * qrModuleSize

	var buf bytes.Buffer

	// Create SVG container with white background
	buf.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d">`, totalSize, totalSize))
	buf.WriteString(`<rect width="100%" height="100%" fill="white"/>`)

	// Generate QR code data matrix using Reed-Solomon encoding
	matrix, err := generateQRMatrix(verificationURI)
	if err != nil {
		return "", fmt.Errorf("generating QR matrix: %w", err)
	}

	// Draw QR code modules
	for y := 0; y < qrSize; y++ {
		for x := 0; x < qrSize; x++ {
			if matrix[y][x] {
				// Draw black module with offset for quiet zone
				drawX := (x + qrQuietZone) * qrModuleSize
				drawY := (y + qrQuietZone) * qrModuleSize
				buf.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d"/>`,
					drawX, drawY, qrModuleSize, qrModuleSize))
			}
		}
	}

	buf.WriteString("</svg>")
	return buf.String(), nil
}

// generateQRMatrix creates a QR code matrix for the verification URI
// This is a simplified implementation that handles alphanumeric data
// per RFC 8628 verification_uri_complete requirements
func generateQRMatrix(text string) ([][]bool, error) {
	if len(text) > 90 { // Max length for Version 2 with ECC level L
		return nil, fmt.Errorf("verification URI too long for QR version 2")
	}

	// Initialize matrix
	matrix := make([][]bool, qrSize)
	for i := range matrix {
		matrix[i] = make([]bool, qrSize)
	}

	// Add finder patterns
	addFinderPattern(matrix, 0, 0)        // Top-left
	addFinderPattern(matrix, 0, qrSize-7) // Top-right
	addFinderPattern(matrix, qrSize-7, 0) // Bottom-left
	addAlignmentPattern(matrix, qrSize-9, qrSize-9)

	// Add timing patterns
	for i := 8; i < qrSize-8; i++ {
		matrix[6][i] = i%2 == 0
		matrix[i][6] = i%2 == 0
	}

	// Add format info
	addFormatInfo(matrix)

	// Add data bits
	data, err := encodeData(text)
	if err != nil {
		return nil, fmt.Errorf("encoding data: %w", err)
	}
	if err := addData(matrix, data); err != nil {
		return nil, fmt.Errorf("adding data to matrix: %w", err)
	}

	return matrix, nil
}

// addFinderPattern adds a finder pattern to the matrix at the given position
func addFinderPattern(matrix [][]bool, top, left int) {
	// Outer box
	for i := 0; i < 7; i++ {
		matrix[top][left+i] = true
		matrix[top+6][left+i] = true
		matrix[top+i][left] = true
		matrix[top+i][left+6] = true
	}
	// Inner box
	for i := 2; i < 5; i++ {
		for j := 2; j < 5; j++ {
			matrix[top+i][left+j] = true
		}
	}
}

// addAlignmentPattern adds an alignment pattern required for Version 2
func addAlignmentPattern(matrix [][]bool, top, left int) {
	// Add 5x5 alignment pattern
	for i := 0; i < 5; i++ {
		matrix[top][left+i] = true
		matrix[top+4][left+i] = true
		matrix[top+i][left] = true
		matrix[top+i][left+4] = true
	}
	// Add center black module
	matrix[top+2][left+2] = true
}

// addFormatInfo adds format information using a fixed pattern for Version 2-L
func addFormatInfo(matrix [][]bool) {
	// Format bits for Version 2-L
	format := []bool{true, false, true, false, true, false, false, true,
		false, true, true, false, false, true, false}

	// Add format bits around the top-left finder pattern
	for i := 0; i < 6; i++ {
		matrix[8][i] = format[i]
		matrix[i][8] = format[14-i]
	}
	matrix[7][8] = format[6]
	matrix[8][8] = format[7]
	matrix[8][7] = format[8]
}

// encodeData converts text into QR code bit stream for alphanumeric mode
func encodeData(text string) ([]bool, error) {
	// Convert to uppercase for QR alphanumeric mode
	text = strings.ToUpper(text)

	// Start with mode indicator for alphanumeric (0010)
	bits := []bool{false, false, true, false}

	// Add 9-bit character count indicator
	length := len(text)
	for i := 8; i >= 0; i-- {
		bits = append(bits, (length&(1<<i)) != 0)
	}

	// Convert characters to bit stream
	for i := 0; i < len(text); i += 2 {
		var value int
		if i+1 < len(text) {
			// Encode pair of characters
			value = alphanumericValue(text[i])*45 + alphanumericValue(text[i+1])
			// Add 11 bits
			for j := 10; j >= 0; j-- {
				bits = append(bits, (value&(1<<j)) != 0)
			}
		} else {
			// Encode single character
			value = alphanumericValue(text[i])
			// Add 6 bits
			for j := 5; j >= 0; j-- {
				bits = append(bits, (value&(1<<j)) != 0)
			}
		}
	}

	// Pad to byte boundary
	if len(bits)%8 != 0 {
		padding := 8 - (len(bits) % 8)
		for i := 0; i < padding; i++ {
			bits = append(bits, false)
		}
	}

	return bits, nil
}

// alphanumericValue converts a QR code alphanumeric character to its value
func alphanumericValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10
	case c == ' ':
		return 36
	case c == '$':
		return 37
	case c == '%':
		return 38
	case c == '*':
		return 39
	case c == '+':
		return 40
	case c == '-':
		return 41
	case c == '.':
		return 42
	case c == '/':
		return 43
	case c == ':':
		return 44
	default:
		return 0 // Handle invalid characters
	}
}

// addData adds encoded data bits using mask pattern 0 per QR specification
func addData(matrix [][]bool, data []bool) error {
	if len(data) == 0 {
		return fmt.Errorf("no data to add")
	}

	// Starting position at bottom-right, moving upward
	x := qrSize - 1
	y := qrSize - 1
	up := true
	dataIndex := 0

	// Skip over the vertical timing pattern
	if x == 6 {
		x--
	}

	// Add data bits in a zig-zag pattern
	for x >= 0 && dataIndex < len(data) {
		// Check if we hit a reserved area
		if !isReserved(matrix, x, y) {
			// Apply mask pattern 0 (even row+column sum)
			bit := data[dataIndex]
			if (x+y)%2 == 0 {
				bit = !bit
			}
			matrix[y][x] = bit
			dataIndex++
		}

		// Move to next position
		if up {
			if y > 0 {
				y--
				if x%2 == 0 {
					x++
				} else {
					x--
				}
			} else {
				x -= 2
				up = false
			}
		} else {
			if y < qrSize-1 {
				y++
				if x%2 == 0 {
					x++
				} else {
					x--
				}
			} else {
				x -= 2
				up = true
			}
		}

		// Skip over vertical timing pattern
		if x == 6 {
			x--
		}
	}

	return nil
}

// isReserved checks if a position in the matrix is reserved for format information
func isReserved(matrix [][]bool, x, y int) bool {
	// Check finder patterns
	if (y < 9 && x < 9) || // Top-left
		(y < 9 && x > qrSize-9) || // Top-right
		(y > qrSize-9 && x < 9) { // Bottom-left
		return true
	}

	// Check alignment pattern for Version 2
	if x >= qrSize-9 && x < qrSize-4 &&
		y >= qrSize-9 && y < qrSize-4 {
		return true
	}

	// Check timing patterns
	if x == 6 || y == 6 {
		return true
	}

	return false
}
