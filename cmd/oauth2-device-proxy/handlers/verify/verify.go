package verify

import (
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
	flow      *deviceflow.Flow
	templates *templates.Templates
	csrf      *csrf.Manager
	oauth     *oauth2.Config
	baseURL   string
}

// Config contains handler configuration
type Config struct {
	Flow      *deviceflow.Flow
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

// HandleForm shows the verification form
func (h *Handler) HandleForm(w http.ResponseWriter, r *http.Request) {
	// Generate CSRF token
	token, err := h.csrf.GenerateToken(r.Context())
	if err != nil {
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "System Error",
			Message: "Unable to process request. Please try again.",
		}); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
		return
	}

	// Get prefilled code from query string
	code := r.URL.Query().Get("code")

	// Generate QR code if verification_uri_complete is supported
	verificationURI := h.baseURL + "/device"
	qrCode := ""
	if code != "" {
		uri := verificationURI + "?code=" + url.QueryEscape(code)
		qrCode, err = h.templates.GenerateQRCode(uri)
		if err != nil {
			// QR code generation failure is non-fatal
			if renderErr := h.templates.RenderError(w, templates.ErrorData{
				Title:   "QR Code Generation Failed",
				Message: "The QR code could not be generated, but you can still enter the code manually.",
			}); renderErr != nil {
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}
		}
	}

	// Render verification form
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

// HandleSubmit processes the verification form submission
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Verify CSRF token
	if err := h.csrf.ValidateToken(r.Context(), r.PostFormValue("csrf_token")); err != nil {
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
	deviceCode, err := h.flow.VerifyUserCode(r.Context(), code)
	if err != nil {
		data := templates.VerifyData{
			Error:     "Invalid or expired code. Please try again.",
			CSRFToken: r.PostFormValue("csrf_token"),
		}
		if err := h.templates.RenderVerify(w, data); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
		return
	}

	// Code is valid - redirect to OAuth provider
	params := map[string]string{
		"response_type": "code",
		"client_id":     deviceCode.ClientID,
		"redirect_uri":  h.baseURL + "/device/complete",
		"state":         deviceCode.DeviceCode,
	}
	if deviceCode.Scope != "" {
		params["scope"] = deviceCode.Scope
	}

	http.Redirect(w, r, h.buildOAuthURL(params), http.StatusFound)
}

// HandleComplete processes the OAuth callback and completes device authorization
func (h *Handler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.URL.Query().Get("state")
	if deviceCode == "" {
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
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "No authorization code received",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Load device code details to preserve scope
	dCode, err := h.flow.GetDeviceCode(r.Context(), deviceCode)
	if err != nil {
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "Device code verification failed",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Exchange code for token
	token, err := h.exchangeCode(r.Context(), authCode, dCode)
	if err != nil {
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "Unable to complete authorization",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Complete the device authorization
	if err := h.flow.CompleteAuthorization(r.Context(), deviceCode, token); err != nil {
		if err := h.templates.RenderError(w, templates.ErrorData{
			Title:   "Authorization Failed",
			Message: "Unable to complete device authorization",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Show success page
	if err := h.templates.RenderComplete(w, templates.CompleteData{
		Message: "You have successfully authorized the device. You may now close this window.",
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// buildOAuthURL constructs the authorization endpoint URL with parameters
func (h *Handler) buildOAuthURL(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	return h.oauth.Endpoint.AuthURL + "?" + values.Encode()
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
