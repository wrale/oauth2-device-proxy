// Package integration provides end-to-end testing for OAuth 2.0 Device Flow implementation
package integration

// Response types as defined in RFC 8628 Section 3.2
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`               // REQUIRED
	UserCode                string `json:"user_code"`                 // REQUIRED
	VerificationURI         string `json:"verification_uri"`          // REQUIRED
	VerificationURIComplete string `json:"verification_uri_complete"` // OPTIONAL
	ExpiresIn               int    `json:"expires_in"`                // REQUIRED
	Interval                int    `json:"interval"`                  // REQUIRED if polling supported
}

// Token response as defined in RFC 8628 Section 3.5
type tokenResponse struct {
	AccessToken  string `json:"access_token"`  // REQUIRED
	TokenType    string `json:"token_type"`    // REQUIRED - Value MUST be "Bearer"
	ExpiresIn    int    `json:"expires_in"`    // RECOMMENDED
	RefreshToken string `json:"refresh_token"` // OPTIONAL
	Scope        string `json:"scope"`         // OPTIONAL if identical to request scope
}

// Error response format as defined in RFC 6749 Section 5.2
type errorResponse struct {
	Error            string `json:"error"`             // REQUIRED
	ErrorDescription string `json:"error_description"` // OPTIONAL
}

// Known error codes defined in RFC 8628 Section 3.5
const (
	ErrAuthorizationPending = "authorization_pending"
	ErrSlowDown             = "slow_down"
	ErrAccessDenied         = "access_denied"
	ErrExpiredToken         = "expired_token"
	ErrInvalidRequest       = "invalid_request"
	ErrInvalidGrant         = "invalid_grant"
)
