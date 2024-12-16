// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
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

// writeResponse writes a response safely, logging any errors
func (h *Handler) writeResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	if _, err := w.Write([]byte(message)); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}

// renderError handles error page rendering with proper status code
func (h *Handler) renderError(w http.ResponseWriter, status int, title, message string) {
	w.WriteHeader(status)
	if err := h.templates.RenderError(w, templates.ErrorData{
		Title:   title,
		Message: message,
	}); err != nil {
		log.Printf("Failed to render error page: %v", err)
		// Since WriteHeader was already called, write plain text with error checking
		h.writeResponse(w, status, message)
	}
}

// renderVerify handles verify form rendering with proper status code
func (h *Handler) renderVerify(w http.ResponseWriter, status int, data templates.VerifyData) {
	w.WriteHeader(status)
	if err := h.templates.RenderVerify(w, data); err != nil {
		log.Printf("Failed to render verify page: %v", err)
		// Headers already sent, write plain text with error checking
		h.writeResponse(w, status, "Verification form display error")
	}
}

// HandleForm shows the verification form per RFC 8628 section 3.3
func (h *Handler) HandleForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Generate CSRF token first - failure is critical security issue per RFC 8628
	token, err := h.csrf.GenerateToken(ctx)
	if err != nil {
		h.renderError(w, http.StatusInternalServerError,
			"Security Error",
			"Unable to process request securely. Please try again.")
		return
	}

	// Get prefilled code from query string
	code := r.URL.Query().Get("code")

	// Set up verification data
	verificationURI := h.baseURL + "/device"
	data := templates.VerifyData{
		PrefilledCode:   code,
		CSRFToken:       token,
		VerificationURI: verificationURI,
	}

	// Generate QR code if code provided
	// QR failures are non-fatal per RFC 8628 section 3.3.1
	if code != "" {
		completeURI := verificationURI + "?code=" + url.QueryEscape(code)
		if qrCode, err := h.templates.GenerateQRCode(completeURI); err != nil {
			// Log warning only - QR code is an optimization
			log.Printf("Warning: QR code generation failed: %v", err)
		} else {
			data.VerificationQRCodeSVG = qrCode
		}
	}

	// Render verification form with 200 OK per RFC 8628 section 3.3
	h.renderVerify(w, http.StatusOK, data)
}

// HandleSubmit processes the verification form submission per RFC 8628 section 3.3
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse form first
	if err := r.ParseForm(); err != nil {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"Unable to process form submission")
		return
	}

	// CSRF validation is security check - per RFC 8628 it fails securely
	if err := h.csrf.ValidateToken(ctx, r.PostFormValue("csrf_token")); err != nil {
		h.renderError(w, http.StatusInternalServerError,
			"Security Error",
			"Invalid security token. Please try again.")
		return
	}

	// Get and validate user code
	code := r.PostFormValue("code")
	if code == "" {
		h.renderError(w, http.StatusBadRequest,
			"Missing Code",
			"No device code was entered")
		return
	}

	// Verify code with device flow manager
	deviceCode, err := h.flow.VerifyUserCode(ctx, code)
	if err != nil {
		// Invalid codes show form again with error and 200 OK per RFC 8628
		h.renderVerify(w, http.StatusOK, templates.VerifyData{
			Error:     "Invalid or expired code. Please try again.",
			CSRFToken: r.PostFormValue("csrf_token"),
		})
		return
	}

	// Build OAuth authorization URL per RFC 8628 section 3.3
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", deviceCode.ClientID)
	params.Set("redirect_uri", h.baseURL+"/device/complete")
	params.Set("state", deviceCode.DeviceCode) // Use device code as state per RFC 8628
	if deviceCode.Scope != "" {
		params.Set("scope", deviceCode.Scope)
	}

	// Redirect to authorization URL with 302 Found per RFC 8628 section 3.3
	authURL := h.oauth.Endpoint.AuthURL + "?" + params.Encode()
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusFound)
}

// HandleComplete processes the OAuth callback and completes device authorization
func (h *Handler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Verify state matches device code per RFC 8628
	deviceCode := r.URL.Query().Get("state")
	if deviceCode == "" {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"Missing state parameter")
		return
	}

	// Verify auth code presence
	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"No authorization code received")
		return
	}

	// Load device code details
	dCode, err := h.flow.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"Device code verification failed")
		return
	}

	// Exchange code for token
	token, err := h.exchangeCode(ctx, authCode, dCode)
	if err != nil {
		h.renderError(w, http.StatusInternalServerError,
			"Authorization Failed",
			"Unable to complete authorization")
		return
	}

	// Complete device authorization
	if err := h.flow.CompleteAuthorization(ctx, deviceCode, token); err != nil {
		h.renderError(w, http.StatusInternalServerError,
			"Server Error",
			"Unable to complete device authorization")
		return
	}

	// Show success page with 200 OK per RFC 8628
	if err := h.templates.RenderComplete(w, templates.CompleteData{
		Message: "You have successfully authorized the device. You may now close this window.",
	}); err != nil {
		log.Printf("Failed to render completion page: %v", err)
		// Since headers not sent yet, we can still show error
		h.renderError(w, http.StatusInternalServerError,
			"Display Error",
			"Successfully authorized but unable to show completion page")
		return
	}
}

// exchangeCode exchanges an authorization code for tokens
func (h *Handler) exchangeCode(ctx context.Context, code string, deviceCode *deviceflow.DeviceCode) (*deviceflow.TokenResponse, error) {
	token, err := h.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}

	return &deviceflow.TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		RefreshToken: token.RefreshToken,
		Scope:        deviceCode.Scope,
	}, nil
}
