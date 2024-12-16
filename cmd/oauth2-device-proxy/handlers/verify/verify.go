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

	// Generate CSRF token - treat failures as critical errors
	token, err := h.csrf.GenerateToken(ctx)
	if err != nil {
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "System Error",
			Message: "Unable to process request. Please try again.",
		}); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
		return
	}

	// Get prefilled code from query string and strip spaces
	code := r.URL.Query().Get("code")

	// Generate QR code for verification_uri_complete (RFC 8628 section 3.3.1)
	verificationURI := h.baseURL + "/device"
	var qrCode string
	if code != "" {
		uri := verificationURI + "?code=" + url.QueryEscape(code)
		qrCode, err = h.templates.GenerateQRCode(uri)
		if err != nil {
			// QR code generation is non-fatal per RFC 8628 section 3.3.1
			qrCode = "" // Gracefully degrade to text-only display
		}
	}

	// Render verification form with QR code
	data := templates.VerifyData{
		PrefilledCode:         code,
		CSRFToken:             token,
		VerificationURI:       verificationURI,
		VerificationQRCodeSVG: qrCode,
	}

	if err := h.templates.RenderVerify(w, data); err != nil {
		http.Error(w, "error rendering page", http.StatusInternalServerError)
	}
}

// HandleSubmit processes the verification form submission per RFC 8628 section 3.3
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Invalid Request",
			Message: "Unable to process form submission",
		}); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
		return
	}

	// Verify CSRF token - treat failures as user errors
	if err := h.csrf.ValidateToken(ctx, r.PostFormValue("csrf_token")); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Invalid Request",
			Message: "Please try submitting the form again.",
		}); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
		return
	}

	// Get and validate the user code
	code := r.PostFormValue("code")
	if code == "" {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Invalid Request",
			Message: "No device code was entered",
		}); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
		return
	}

	// Verify code with device flow manager
	deviceCode, err := h.flow.VerifyUserCode(ctx, code)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		data := templates.VerifyData{
			Error:     "Invalid or expired code. Please try again.",
			CSRFToken: r.PostFormValue("csrf_token"),
		}
		if err := h.templates.RenderVerify(w, data); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
		return
	}

	// Code is valid - redirect to OAuth provider per RFC 8628 section 3.3
	params := url.Values{
		"response_type": []string{"code"},
		"client_id":     []string{deviceCode.ClientID},
		"redirect_uri":  []string{h.baseURL + "/device/complete"},
		"state":         []string{deviceCode.DeviceCode},
	}
	if deviceCode.Scope != "" {
		params.Set("scope", deviceCode.Scope)
	}

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
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Invalid Request",
			Message: "Missing or invalid state parameter",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	authCode := r.URL.Query().Get("code")
	if authCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "No authorization code received",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Load device code details to preserve scope
	dCode, err := h.flow.GetDeviceCode(ctx, deviceCode)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "Device code verification failed",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Complete the device authorization
	if err := h.flow.CompleteAuthorization(ctx, deviceCode, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "Unable to complete device authorization",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Show success page per RFC 8628 section 3.3
	if err := h.templates.RenderComplete(w, templates.CompleteData{
		Message: "You have successfully authorized the device. You may now close this window.",
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
