// Package deviceflow implements URI handling for OAuth 2.0 Device Flow
package deviceflow

import (
	"net/url"
	"path"

	"github.com/wrale/oauth2-device-proxy/internal/validation"
)

// buildVerificationURIs creates the verification URIs per RFC 8628 sections 3.2 and 3.3.1
// It returns both the base verification URI and the complete URI that includes the user code:
// - verification_uri: The base URI that users can visit to enter their code
// - verification_uri_complete: Optional URI that includes the user code (e.g., for QR codes)
func (f *flowImpl) buildVerificationURIs(userCode string) (string, string) {
	// Parse the base URL to properly handle existing paths
	baseURL, err := url.Parse(f.baseURL)
	if err != nil {
		return "", "" // Invalid base URL
	}

	// Combine existing path with device endpoint
	baseURL.Path = path.Join(baseURL.Path, "device")
	verificationURI := baseURL.String()

	// Validate the user code
	if err := validation.ValidateUserCode(userCode); err != nil {
		return verificationURI, "" // Return base URI only if code invalid
	}

	// Create verification URI with code per RFC section 3.3.1
	completeURL := *baseURL // Make a copy for the complete URI
	q := completeURL.Query()
	q.Set("code", userCode) // Use display format per RFC section 6.1
	completeURL.RawQuery = q.Encode()

	return verificationURI, completeURL.String()
}
