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

// HandleForm shows the verification form per RFC 8628 section 3.3
func (h *Handler) HandleForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Generate CSRF token first - failure is critical
	token, err := h.csrf.GenerateToken(ctx)
	if err != nil {
		// Set status before writing error response
		w.WriteHeader(http.StatusInternalServerError)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Server Error",
			Message: "Unable to process request. Please try again.",
		}); err != nil {
			log.Printf("Failed to render error page: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
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

	// Generate QR code if code provided, but QR failures are non-fatal per RFC 8628 3.3.1
	if code != "" {
		completeURI := verificationURI + "?code=" + url.QueryEscape(code)
		if qrCode, err := h.templates.GenerateQRCode(completeURI); err != nil {
			// Log warning only - QR code is an optimization
			log.Printf("Warning: QR code generation failed: %v", err)
		} else {
			data.VerificationQRCodeSVG = qrCode
		}
	}

	// Set status before writing response
	w.WriteHeader(http.StatusOK)
	if err := h.templates.RenderVerify(w, data); err != nil {
		log.Printf("Failed to render verification form: %v", err)
		// Headers already sent, cannot render error page
		return
	}
}

// HandleSubmit processes the verification form submission per RFC 8628 section 3.3
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse form first
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if rErr := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Bad Request",
			Message: "Unable to process form submission",
		}); rErr != nil {
			log.Printf("Failed to render error page: %v", rErr)
			http.Error(w, "Bad request", http.StatusBadRequest)
		}
		return
	}

	// CSRF validation is a critical security check - treat failures as server errors
	if err := h.csrf.ValidateToken(ctx, r.PostFormValue("csrf_token")); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		if rErr := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Security Error",
			Message: "Invalid security token. Please try again.",
		}); rErr != nil {
			log.Printf("Failed to render error page: %v", rErr)
			http.Error(w, "Security error", http.StatusInternalServerError)
		}
		return
	}

	// Get and validate user code
	code := r.PostFormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Missing Code",
			Message: "No device code was entered",
		}); err != nil {
			log.Printf("Failed to render error page: %v", err)
			http.Error(w, "Missing code", http.StatusBadRequest)
		}
		return
	}

	// Verify code with device flow manager
	deviceCode, err := h.flow.VerifyUserCode(ctx, code)
	if err != nil {
		// Show form again with error but preserve CSRF token
		if err := h.templates.RenderVerify(w, templates.VerifyData{
			Error:     "Invalid or expired code. Please try again.",
			CSRFToken: r.PostFormValue("csrf_token"),
		}); err != nil {
			log.Printf("Failed to render verification form with error: %v", err)
			// Fallback to error page since form failed
			if rErr := h.templates.RenderError(w, templates.ErrorData{
				Title:   "Error",
				Message: "Invalid code. Please try again.",
			}); rErr != nil {
				log.Printf("Failed to render error page: %v", rErr)
				http.Error(w, "Invalid code", http.StatusBadRequest)
			}
		}
		return
	}

	// Build OAuth authorization URL per RFC 8628 section 3.3
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", deviceCode.ClientID)
	params.Set("redirect_uri", h.baseURL+"/device/complete")
	params.Set("state", deviceCode.DeviceCode)
	if deviceCode.Scope != "" {
		params.Set("scope", deviceCode.Scope)
	}

	// Redirect to authorization URL - set header first per HTTP spec
	location := h.oauth.Endpoint.AuthURL + "?" + params.Encode()
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// HandleComplete processes the OAuth callback and completes device authorization
func (h *Handler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Verify state first to prevent CSRF
	deviceCode := r.URL.Query().Get("state")
	if deviceCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Invalid Request",
			Message: "Missing or invalid state parameter",
		}); err != nil {
			log.Printf("Failed to render error page: %v", err)
			http.Error(w, "Invalid state", http.StatusBadRequest)
		}
		return
	}

	// Verify auth code presence
	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Invalid Request",
			Message: "No authorization code received",
		}); err != nil {
			log.Printf("Failed to render error page: %v", err)
			http.Error(w, "Missing code", http.StatusBadRequest)
		}
		return
	}

	// Load device code details
	dCode, err := h.flow.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Invalid Request",
			Message: "Device code verification failed",
		}); err != nil {
			log.Printf("Failed to render error page: %v", err)
			http.Error(w, "Invalid device code", http.StatusBadRequest)
		}
		return
	}

	// Exchange code for token
	token, err := h.exchangeCode(ctx, authCode, dCode)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "Unable to complete authorization",
		}); err != nil {
			log.Printf("Failed to render error page: %v", err)
			http.Error(w, "Authorization failed", http.StatusBadRequest)
		}
		return
	}

	// Complete device authorization
	if err := h.flow.CompleteAuthorization(ctx, deviceCode, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Server Error",
			Message: "Unable to complete device authorization",
		}); err != nil {
			log.Printf("Failed to render error page: %v", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}

	// Show success page per RFC 8628 section 3.3
	w.WriteHeader(http.StatusOK)
	if err := h.templates.RenderComplete(w, templates.CompleteData{
		Message: "You have successfully authorized the device. You may now close this window.",
	}); err != nil {
		log.Printf("Failed to render completion page: %v", err)
		// Headers already sent, cannot render error page
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
