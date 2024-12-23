// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"log"
	"net/http"
	"net/url"
	"path"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// HandleForm shows the verification form per RFC 8628 section 3.3
func (h *Handler) HandleForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Generate CSRF token for security
	token, err := h.csrf.GenerateToken(ctx)
	if err != nil {
		// CSRF failures return 400 Bad Request per RFC 8628
		w.WriteHeader(http.StatusBadRequest)
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

	// Set 200 OK status now for successful form display per RFC 8628 section 3.3
	w.WriteHeader(http.StatusOK)

	baseURL.Path = path.Join(baseURL.Path, "device")
	verificationURI := baseURL.String()

	data := templates.VerifyData{
		PrefilledCode:   code,
		CSRFToken:       token,
		VerificationURI: verificationURI,
	}

	// Generate QR code if possible (non-fatal per RFC 8628 section 3.3.1)
	if code != "" {
		completeURI := verificationURI + "?code=" + url.QueryEscape(code)
		qrCode, err := h.templates.GenerateQRCode(completeURI)
		if err != nil {
			// Just log warning - QR code is optional enhancement
			log.Printf("Warning: QR code generation failed: %v", err)
		} else {
			data.VerificationQRCodeSVG = qrCode
		}
	}

	// Render form - errors are already logged in template renderer
	h.renderVerify(w, data)
}
