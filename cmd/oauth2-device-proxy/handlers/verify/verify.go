// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"context"
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

// HandleForm shows the verification form per RFC 8628 section 3.3
func (h *Handler) HandleForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Generate CSRF token
	token, err := h.csrf.GenerateToken(ctx)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "System Error",
			"Unable to process request. Please try again.")
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
		qrCode, err := h.templates.GenerateQRCode(completeURI)
		if err != nil {
			// Non-critical error per RFC 8628 3.3.1 - continue without QR code
			data.Error = "QR code generation failed. Please enter the code manually."
		} else {
			data.VerificationQRCodeSVG = qrCode
		}
	}

	// Set 200 OK status before writing response
	w.WriteHeader(http.StatusOK)
	if err := h.templates.RenderVerify(w, data); err != nil {
		// Response already started - can only log at this point
		http.Error(w, "error rendering page", http.StatusInternalServerError)
	}
}

// HandleSubmit processes the verification form submission per RFC 8628 section 3.3
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid Request",
			"Unable to process form submission")
		return
	}

	// Verify CSRF token
	if err := h.csrf.ValidateToken(ctx, r.PostFormValue("csrf_token")); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid Request",
			"Please try submitting the form again.")
		return
	}

	// Get and validate user code
	code := r.PostFormValue("code")
	if code == "" {
		h.writeError(w, http.StatusBadRequest, "Invalid Request",
			"No device code was entered")
		return
	}

	// Verify code with device flow manager
	deviceCode, err := h.flow.VerifyUserCode(ctx, code)
	if err != nil {
		// Invalid code shows form again with error
		w.WriteHeader(http.StatusOK)
		if err := h.templates.RenderVerify(w, templates.VerifyData{
			Error:     "Invalid or expired code. Please try again.",
			CSRFToken: r.PostFormValue("csrf_token"),
		}); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
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
		h.writeError(w, http.StatusBadRequest, "Invalid Request",
			"Missing or invalid state parameter")
		return
	}

	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		h.writeError(w, http.StatusBadRequest, "Authorization Failed",
			"No authorization code received")
		return
	}

	// Load device code details
	dCode, err := h.flow.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Authorization Failed",
			"Device code verification failed")
		return
	}

	// Exchange code for token
	token, err := h.exchangeCode(ctx, authCode, dCode)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Authorization Failed",
			"Unable to complete authorization")
		return
	}

	// Complete device authorization
	if err := h.flow.CompleteAuthorization(ctx, deviceCode, token); err != nil {
		h.writeError(w, http.StatusInternalServerError, "Authorization Failed",
			"Unable to complete device authorization")
		return
	}

	// Show success page per RFC 8628 section 3.3
	w.WriteHeader(http.StatusOK)
	if err := h.templates.RenderComplete(w, templates.CompleteData{
		Message: "You have successfully authorized the device. You may now close this window.",
	}); err != nil {
		http.Error(w, "error rendering page", http.StatusInternalServerError)
	}
}

// exchangeCode exchanges an authorization code for tokens
func (h *Handler) exchangeCode(ctx context.Context, code string, deviceCode *deviceflow.DeviceCode) (*deviceflow.TokenResponse, error) {
	token, err := h.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return &deviceflow.TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		RefreshToken: token.RefreshToken,
		Scope:        deviceCode.Scope,
	}, nil
}

// writeError handles error responses with proper status codes per RFC 8628
func (h *Handler) writeError(w http.ResponseWriter, status int, title, message string) {
	w.WriteHeader(status)
	if err := h.templates.RenderError(w, templates.ErrorData{
		Title:   title,
		Message: message,
	}); err != nil {
		http.Error(w, "error rendering error page", http.StatusInternalServerError)
	}
}
