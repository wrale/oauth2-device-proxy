// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"net/http"
	"net/url"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// HandleSubmit processes the verification form submission per RFC 8628 section 3.3
func (h *Handler) HandleSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse form first to get input
	if err := r.ParseForm(); err != nil {
		// Client error (400) per RFC 8628 section 3.3
		h.renderError(w, http.StatusBadRequest,
			"Invalid Request",
			"Unable to process form submission. Please try again.")
		return
	}

	// CSRF validation is input validation per RFC 8628 section 3.3
	if err := h.csrf.ValidateToken(ctx, r.PostFormValue("csrf_token")); err != nil {
		h.renderError(w, http.StatusBadRequest,
			"Security Error",
			"Your session has expired. Please try again.")
		return
	}

	// Missing code is a client error per RFC 8628
	code := r.PostFormValue("code")
	if code == "" {
		h.renderError(w, http.StatusBadRequest,
			"Missing Code",
			"Please enter the code shown on your device.")
		return
	}

	// Verify the user code
	deviceCode, err := h.flow.VerifyUserCode(ctx, code)
	if err != nil {
		// Show form again for invalid/expired codes per RFC 8628 section 3.3
		h.renderVerify(w, templates.VerifyData{
			Error:         "The code you entered is invalid or has expired. Please check the code and try again.",
			CSRFToken:     r.PostFormValue("csrf_token"), // Maintain CSRF token
			PrefilledCode: code,                          // Keep code for user convenience
		})
		return
	}

	// Build OAuth authorization URL per RFC 8628
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", deviceCode.ClientID)
	params.Set("redirect_uri", h.baseURL+"/device/complete")
	params.Set("state", deviceCode.DeviceCode) // Use device code as state
	if deviceCode.Scope != "" {
		params.Set("scope", deviceCode.Scope)
	}

	// Set location header before status code
	authURL := h.oauth.Endpoint.AuthURL + "?" + params.Encode()
	w.Header().Set("Location", authURL)

	// Successful verification returns 302 Found per RFC 8628 section 3.3
	w.WriteHeader(http.StatusFound)
}
