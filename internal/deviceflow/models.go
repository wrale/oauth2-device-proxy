package deviceflow

import "time"

// DeviceCode represents the device authorization details per RFC 8628 section 3.2
type DeviceCode struct {
	// Required fields per RFC 8628 section 3.2
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"` // Remaining time in seconds
	Interval        int    `json:"interval"`   // Poll interval in seconds

	// Optional verification_uri_complete field per RFC 8628 section 3.3.1
	// Enables non-textual transmission of the verification URI (e.g., QR codes)
	// The URI includes the user code to minimize user input required
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`

	// Additional fields for internal tracking
	ExpiresAt time.Time `json:"-"` // Absolute expiry time
	ClientID  string    `json:"-"` // OAuth2 client identifier
	Scope     string    `json:"-"` // OAuth2 scope
	LastPoll  time.Time `json:"-"` // Last poll timestamp
}

// TokenResponse represents the OAuth2 token response per RFC 8628 section 3.5
type TokenResponse struct {
	AccessToken  string `json:"access_token"`            // The OAuth2 access token
	TokenType    string `json:"token_type"`              // Token type (usually "Bearer")
	ExpiresIn    int    `json:"expires_in"`              // Token validity in seconds
	RefreshToken string `json:"refresh_token,omitempty"` // Optional refresh token
	Scope        string `json:"scope,omitempty"`         // OAuth2 scope granted
}
