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

// logTemplateError logs a template rendering error and optionally falls back to plain text
func (h *Handler) logTemplateError(err error, operation string) {
	log.Printf("Template error during %s: %v", operation, err)
}

// handleRenderError handles template rendering errors with proper fallbacks
func (h *Handler) handleRenderError(w http.ResponseWriter, err error, fallbackStatus int, fallbackMsg string) {
	// If headers haven't been written yet, try to render error page
	if err := h.templates.RenderError(w, templates.ErrorData{
		Title:   "Error",
		Message: fallbackMsg,
	}); err != nil {
		// If error page fails, fall back to plain text
		h.logTemplateError(err, "error page fallback")
		http.Error(w, fallbackMsg, fallbackStatus)
	}
}

// HandleForm shows the verification form per RFC 8628 section 3.3
func (h *Handler) HandleForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Generate CSRF token
	token, err := h.csrf.GenerateToken(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Server Error",
			Message: "Unable to process request. Please try again.",
		}); err != nil {
			h.logTemplateError(err, "CSRF error")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Get prefilled code from query string
	code := r.URL.Query().Get("code")

	// Generate QR code if code provided
	verificationURI := h.baseURL + "/device"
	data := templates.VerifyData{
		PrefilledCode:   code,
		CSRFToken:       token,
		VerificationURI: verificationURI,
	}

	if code != "" {
		completeURI := verificationURI + "?code=" + url.QueryEscape(code)
		if qrCode, err := h.templates.GenerateQRCode(completeURI); err == nil {
			data.VerificationQRCodeSVG = qrCode
		} else {
			// QR code failures are non-fatal per RFC 8628 3.3.1
			// Log warning but continue without QR code
			log.Printf("Warning: QR code generation failed: %v", err)
		}
	}

	// Set 200 OK status and render verification form
	w.WriteHeader(http.StatusOK)
	if err := h.templates.RenderVerify(w, data); err != nil {
		h.logTemplateError(err, "verification form")
		// Headers already sent, cannot write error response
		return
	}
}

// HandleSubmit processes the verification form submission per RFC 8628 section 3.3
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.handleRenderError(w, err, http.StatusBadRequest, "Unable to process form submission")
		return
	}

	// Verify CSRF token
	if err := h.csrf.ValidateToken(ctx, r.PostFormValue("csrf_token")); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.handleRenderError(w, err, http.StatusBadRequest, "Invalid request. Please try again.")
		return
	}

	// Get and validate user code
	code := r.PostFormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.handleRenderError(w, fmt.Errorf("missing code"), http.StatusBadRequest, "No device code was entered")
		return
	}

	// Verify code with device flow manager
	deviceCode, err := h.flow.VerifyUserCode(ctx, code)
	if err != nil {
		w.WriteHeader(http.StatusOK) // Show form again with error
		if err := h.templates.RenderVerify(w, templates.VerifyData{
			Error:     "Invalid or expired code. Please try again.",
			CSRFToken: r.PostFormValue("csrf_token"),
		}); err != nil {
			h.logTemplateError(err, "verification form with error")
			h.handleRenderError(w, err, http.StatusBadRequest, "Invalid code. Please try again.")
		}
		return
	}

	// Build OAuth URL per RFC 8628 section 3.3
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", deviceCode.ClientID)
	params.Set("redirect_uri", h.baseURL+"/device/complete")
	params.Set("state", deviceCode.DeviceCode)
	if deviceCode.Scope != "" {
		params.Set("scope", deviceCode.Scope)
	}

	// Set redirect location and status
	location := h.oauth.Endpoint.AuthURL + "?" + params.Encode()
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// HandleComplete processes the OAuth callback and completes device authorization
func (h *Handler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	deviceCode := r.URL.Query().Get("state")
	if deviceCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.handleRenderError(w, fmt.Errorf("missing state"), http.StatusBadRequest, "Missing or invalid state parameter")
		return
	}

	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		h.handleRenderError(w, fmt.Errorf("missing code"), http.StatusBadRequest, "No authorization code received")
		return
	}

	// Load device code details
	dCode, err := h.flow.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.handleRenderError(w, err, http.StatusBadRequest, "Device code verification failed")
		return
	}

	// Exchange code for token
	token, err := h.exchangeCode(ctx, authCode, dCode)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		h.handleRenderError(w, err, http.StatusBadRequest, "Unable to complete authorization")
		return
	}

	// Complete device authorization
	if err := h.flow.CompleteAuthorization(ctx, deviceCode, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		h.handleRenderError(w, err, http.StatusInternalServerError, "Unable to complete device authorization")
		return
	}

	// Show success page per RFC 8628 section 3.3
	w.WriteHeader(http.StatusOK)
	if err := h.templates.RenderComplete(w, templates.CompleteData{
		Message: "You have successfully authorized the device. You may now close this window.",
	}); err != nil {
		h.logTemplateError(err, "completion page")
		// Headers already sent, cannot write error response
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
