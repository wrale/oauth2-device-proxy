// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"

	"golang.org/x/oauth2"

	"github.com/wrale/oauth2-device-proxy/internal/csrf"
	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// Handler processes user verification flow per RFC 8628 section 3.3
type Handler struct {
	flow      deviceflow.Flow
	templates *templates.Templates
	csrf      *csrf.Manager
	oauth     *oauth2.Config
	baseURL   string
}

// Config contains handler configuration
type Config struct {
	Flow      deviceflow.Flow
	Templates *templates.Templates
	CSRF      *csrf.Manager
	OAuth     *oauth2.Config
	BaseURL   string
}

// New creates a new verification flow handler
func New(cfg Config) *Handler {
	return &Handler{
		flow:      cfg.Flow,
		templates: cfg.Templates,
		csrf:      cfg.CSRF,
		oauth:     cfg.OAuth,
		baseURL:   cfg.BaseURL,
	}
}

// headerWritten checks if response headers have been written by checking for
// the Written() method that both SafeWriter and common middleware wrappers implement
func headerWritten(w http.ResponseWriter) bool {
	type writeTracker interface {
		Written() bool
	}

	// Check for SafeWriter or any other writer that tracks header state
	if wt, ok := w.(writeTracker); ok {
		return wt.Written()
	}

	// Default to assuming headers not written if we can't determine
	return false
}

// writeResponse writes a response safely, logging any errors
func (h *Handler) writeResponse(w http.ResponseWriter, status int, message string) {
	if !headerWritten(w) {
		w.WriteHeader(status)
	}
	if _, err := w.Write([]byte(message)); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// renderError handles error page rendering with proper status code per RFC 8628
func (h *Handler) renderError(w http.ResponseWriter, status int, title, message string) {
	// Set error status before writing response
	if !headerWritten(w) {
		w.WriteHeader(status)
	}

	if err := h.templates.RenderError(w, templates.ErrorData{
		Title:   title,
		Message: message,
	}); err != nil {
		log.Printf("Failed to render error page: %v", err)
		// Headers already sent, write plain text fallback
		h.writeResponse(w, status, fmt.Sprintf("%s: %s", title, message))
	}
}

// renderVerify handles verify form rendering per RFC 8628 section 3.3
func (h *Handler) renderVerify(w http.ResponseWriter, data templates.VerifyData) {
	// Form display always returns 200 OK per RFC 8628 section 3.3
	if !headerWritten(w) {
		w.WriteHeader(http.StatusOK)
	}

	if err := h.templates.RenderVerify(w, data); err != nil {
		log.Printf("Failed to render verify page: %v", err)
		// Always show form on errors per RFC 8628
		h.writeResponse(w, http.StatusOK, "Please enter your device code to continue.")
	}
}

// HandleForm shows the verification form per RFC 8628 section 3.3
func (h *Handler) HandleForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Generate CSRF token for security
	token, err := h.csrf.GenerateToken(ctx)
	if err != nil {
		// CSRF failures are input validation errors per RFC 8628
		h.renderError(w, http.StatusBadRequest,
			"Security Error",
			"Unable to process request securely. Please try again in a moment.")
		return
	}

	// Get prefilled code from query string
	code := r.URL.Query().Get("code")

	// Prepare verification data with required URI per RFC 8628
	baseURL, err := url.Parse(h.baseURL)
	if err != nil {
		h.renderError(w, http.StatusInternalServerError,
			"Configuration Error",
			"Invalid service configuration. Please try again later.")
		return
	}

	baseURL.Path = path.Join(baseURL.Path, "device")
	verificationURI := baseURL.String()

	data := templates.VerifyData{
		PrefilledCode:   code,
		CSRFToken:       token,
		VerificationURI: verificationURI,
	}

	// Try QR code generation if code provided (non-fatal per RFC 8628 section 3.3.1)
	if code != "" {
		completeURI := verificationURI + "?code=" + url.QueryEscape(code)
		if qrCode, err := h.templates.GenerateQRCode(completeURI); err != nil {
			// Log warning only - QR code is optional enhancement
			log.Printf("Warning: QR code generation failed: %v", err)
		} else {
			data.VerificationQRCodeSVG = qrCode
		}
	}

	// Always show form with 200 OK per RFC 8628 section 3.3
	h.renderVerify(w, data)
}

// HandleSubmit processes the verification form submission per RFC 8628 section 3.3
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse form first to get input
	if err := r.ParseForm(); err != nil {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"Unable to process form submission. Please try again.")
		return
	}

	// CSRF validation is input validation - use 400 for invalid tokens
	if err := h.csrf.ValidateToken(ctx, r.PostFormValue("csrf_token")); err != nil {
		h.renderError(w, http.StatusBadRequest,
			"Security Error",
			"Your session has expired. Please try again.")
		return
	}

	// Get and validate user code presence
	code := r.PostFormValue("code")
	if code == "" {
		// Missing code is a client error
		h.renderError(w, http.StatusBadRequest,
			"Missing Code",
			"Please enter the code shown on your device.")
		return
	}

	// Verify code with device flow manager
	deviceCode, err := h.flow.VerifyUserCode(ctx, code)
	if err != nil {
		// Show form again for invalid/expired codes per RFC 8628 section 3.3
		h.renderVerify(w, templates.VerifyData{
			Error:     "The code you entered is invalid or has expired. Please check the code and try again.",
			CSRFToken: r.PostFormValue("csrf_token"), // Maintain CSRF token
		})
		return
	}

	// Build OAuth authorization URL per RFC 8628 section 3.3
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", deviceCode.ClientID)
	params.Set("redirect_uri", h.baseURL+"/device/complete")
	params.Set("state", deviceCode.DeviceCode) // Use device code as state
	if deviceCode.Scope != "" {
		params.Set("scope", deviceCode.Scope)
	}

	// Successful verification redirects with 302 Found per RFC 8628
	authURL := h.oauth.Endpoint.AuthURL + "?" + params.Encode()
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusFound)
}

// HandleComplete processes the OAuth callback and completes device authorization
func (h *Handler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Verify state matches device code
	deviceCode := r.URL.Query().Get("state")
	if deviceCode == "" {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"Unable to verify authorization source. Please try again.")
		return
	}

	// Verify auth code presence
	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"No authorization received. Please try again.")
		return
	}

	// Load device code details
	dCode, err := h.flow.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"Unable to verify device code. Please start over.")
		return
	}

	// Exchange code for token
	token, err := h.exchangeCode(ctx, authCode, dCode)
	if err != nil {
		h.renderError(w, http.StatusInternalServerError,
			"Authorization Failed",
			"Unable to complete device authorization. Please try again.")
		return
	}

	// Complete device authorization
	if err := h.flow.CompleteAuthorization(ctx, deviceCode, token); err != nil {
		h.renderError(w, http.StatusInternalServerError,
			"Server Error",
			"Unable to save authorization. Your device may need to start over.")
		return
	}

	// Show success page with 200 OK per RFC 8628
	if err := h.templates.RenderComplete(w, templates.CompleteData{
		Message: "You have successfully authorized the device. You may now close this window and return to your device.",
	}); err != nil {
		log.Printf("Failed to render completion page: %v", err)
		h.renderError(w, http.StatusOK, // Use 200 per RFC 8628
			"Authorization Complete",
			"Device successfully authorized. You may close this window.")
	}
}

// exchangeCode exchanges an authorization code for tokens
func (h *Handler) exchangeCode(ctx context.Context, code string, deviceCode *deviceflow.DeviceCode) (*deviceflow.TokenResponse, error) {
	// Exchange code using OAuth2 config
	token, err := h.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code: %w", err)
	}

	// Convert oauth2.Token to deviceflow.TokenResponse per RFC 8628
	return &deviceflow.TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		RefreshToken: token.RefreshToken,
		Scope:        deviceCode.Scope,
	}, nil
}
