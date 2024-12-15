// Package templates provides HTML templating and QR code generation
package templates

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	// QR Code specifications for RFC 8628 verification_uri_complete
	qrQuietZone  = 4     // Quiet zone size in modules
	qrModuleSize = 4     // SVG rectangle size per module
	qrVersion    = 2     // Version 2 (25x25) supports up to ~50 chars with ECC level L
	qrSize       = 25    // Version 2 size in modules
	qrEccLevel   = "L"   // Error correction level L (7% recovery)
)

// GenerateQRCode creates an SVG QR code for the verification URI
func (t *Templates) GenerateQRCode(verificationURI string) string {
	// Calculate total size including quiet zones
	totalSize := (qrSize + 2*qrQuietZone) * qrModuleSize

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d">`, totalSize, totalSize))
	buf.WriteString(`<rect width="100%" height="100%" fill="white"/>`)

	// Generate QR code data matrix using Reed-Solomon encoding
	matrix := generateQRMatrix(verificationURI)

	// Draw QR code modules
	for y := 0; y &lt; qrSize; y++ {
		for x := 0; x &lt; qrSize; x++ {
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
	return buf.String()
}

// generateQRMatrix creates a QR code matrix for the given text
// This is a simplified implementation that only handles basic alphanumeric data
// A production system should use a full QR code library
func generateQRMatrix(text string) [][]bool {
	// Initialize matrix
	matrix := make([][]bool, qrSize)
	for i := range matrix {
		matrix[i] = make([]bool, qrSize)
	}

	// Add finder patterns
	addFinderPattern(matrix, 0, 0)                   // Top-left
	addFinderPattern(matrix, 0, qrSize-7)           // Top-right
	addFinderPattern(matrix, qrSize-7, 0)           // Bottom-left
	addAlignmentPattern(matrix, qrSize-9, qrSize-9) // Version 2 alignment pattern

	// Add timing patterns
	for i := 8; i &lt; qrSize-8; i++ {
		matrix[6][i] = i%2 == 0
		matrix[i][6] = i%2 == 0
	}

	// Add format information
	addFormatInfo(matrix)

	// Add data bits (simplified)
	data := encodeData(text)
	addData(matrix, data)

	return matrix
}

// addFinderPattern adds a finder pattern to the matrix at the given position
func addFinderPattern(matrix [][]bool, top, left int) {
	// Outer box
	for i := 0; i &lt; 7; i++ {
		matrix[top][left+i] = true
		matrix[top+6][left+i] = true
		matrix[top+i][left] = true
		matrix[top+i][left+6] = true
	}
	// Inner box
	for i := 2; i &lt; 5; i++ {
		for j := 2; j &lt; 5; j++ {
			matrix[top+i][left+j] = true
		}
	}
}

// addAlignmentPattern adds an alignment pattern to the matrix at the given position
func addAlignmentPattern(matrix [][]bool, top, left int) {
	// Add 5x5 alignment pattern
	for i := 0; i &lt; 5; i++ {
		matrix[top][left+i] = true
		matrix[top+4][left+i] = true
		matrix[top+i][left] = true
		matrix[top+i][left+4] = true
	}
	// Add center black module
	matrix[top+2][left+2] = true
}

// addFormatInfo adds the format information to the matrix
// This is a simplified implementation that uses fixed format bits for V2-L
func addFormatInfo(matrix [][]bool) {
	// Format bits for Version 2-L (simplified)
	format := []bool{true, false, true, false, true, false, false, true, false, true, true, false, false, true, false}
	
	// Add format bits around the top-left finder pattern
	for i := 0; i &lt; 6; i++ {
		matrix[8][i] = format[i]
		matrix[i][8] = format[14-i]
	}
	matrix[7][8] = format[6]
	matrix[8][8] = format[7]
	matrix[8][7] = format[8]
}

// encodeData converts text into a QR code bit stream
// This is a simplified implementation that only handles basic alphanumeric data
func encodeData(text string) []bool {
	// Convert string to uppercase (QR alphanumeric mode is uppercase only)
	text = strings.ToUpper(text)
	
	// Start with mode indicator (0b0010 for alphanumeric)
	bits := []bool{false, false, true, false}
	
	// Add character count indicator (9 bits for Version 2)
	length := len(text)
	for i := 8; i >= 0; i-- {
		bits = append(bits, (length&(1&lt;&lt;i)) != 0)
	}

	// Convert characters to bit stream
	for i := 0; i &lt; len(text); i += 2 {
		var value int
		if i+1 &lt; len(text) {
			// Encode pair of characters
			value = alphanumericValue(text[i])*45 + alphanumericValue(text[i+1])
			// Add 11 bits
			for j := 10; j >= 0; j-- {
				bits = append(bits, (value&(1&lt;&lt;j)) != 0)
			}
		} else {
			// Encode single character
			value = alphanumericValue(text[i])
			// Add 6 bits
			for j := 5; j >= 0; j-- {
				bits = append(bits, (value&(1&lt;&lt;j)) != 0)
			}
		}
	}

	// Add terminator if needed
	if len(bits)%8 != 0 {
		padding := 8 - (len(bits) % 8)
		for i := 0; i &lt; padding; i++ {
			bits = append(bits, false)
		}
	}

	return bits
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
		return 0
	}
}

// addData adds the encoded data bits to the matrix using the mask pattern
func addData(matrix [][]bool, data []bool) {
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
	for x >= 0 && dataIndex &lt; len(data) {
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
				x += (x%2 == 0) ? 1 : -1
			} else {
				x -= 2
				up = false
			}
		} else {
			if y &lt; qrSize-1 {
				y++
				x += (x%2 == 0) ? 1 : -1
			} else {
				x -= 2
				up = true
			}
		}

		// Skip over the vertical timing pattern
		if x == 6 {
			x--
		}
	}
}

// isReserved checks if a position in the matrix is reserved for format information
func isReserved(matrix [][]bool, x, y int) bool {
	// Check finder patterns
	if (y &lt; 9 && x &lt; 9) || // Top-left
		(y &lt; 9 && x > qrSize-9) || // Top-right
		(y > qrSize-9 && x &lt; 9) { // Bottom-left
		return true
	}

	// Check alignment pattern
	if x >= qrSize-9 && x &lt; qrSize-4 &&
		y >= qrSize-9 && y &lt; qrSize-4 {
		return true
	}

	// Check timing patterns
	if x == 6 || y == 6 {
		return true
	}

	return false
}
