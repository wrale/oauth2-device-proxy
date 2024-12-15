// Package deviceflow implements URI handling for OAuth 2.0 Device Flow
package deviceflow

import (
	"net/url"
	"strings"

	"github.com/jmdots/oauth2-device-proxy/internal/validation"
)

// buildVerificationURIs creates the verification URIs per RFC 8628 sections 3.2 and 3.3.1
// It returns both the base verification URI and the complete URI that includes the user code:
// - verification_uri: The base URI that users can visit to enter their code
// - verification_uri_complete: Optional URI that includes the user code (e.g., for QR codes)
func (f *Flow) buildVerificationURIs(userCode string) (string, string) {
	// Ensure base URL ends with no trailing slash
	baseURL := strings.TrimSuffix(f.baseURL, "/")
	verificationURI := baseURL + "/device"

	// Only include code in complete URI if it's valid
	if err := validation.ValidateUserCode(userCode); err != nil {
		return verificationURI, "" // Return base URI only if code invalid
	}

	// Create verification URI with code per RFC section 3.3.1
	query := url.Values{}
	query.Set("code", userCode) // Use display format
	verificationURIComplete := verificationURI + "?" + query.Encode()

	return verificationURI, verificationURIComplete
}
