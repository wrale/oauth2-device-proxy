// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"log"
	"net/http"

	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

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
