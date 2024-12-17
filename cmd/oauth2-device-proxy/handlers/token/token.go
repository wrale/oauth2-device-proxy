package token

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/wrale/oauth2-device-proxy/cmd/oauth2-device-proxy/handlers/common"
	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

// Handler processes device access token requests per RFC 8628 section 3.4
type Handler struct {
	flow deviceflow.Flow // Changed from *deviceflow.Flow to deviceflow.Flow
}

// Config contains handler configuration options
type Config struct {
	Flow deviceflow.Flow // Added Config struct for consistency
}

// New creates a new token request handler
func New(cfg Config) *Handler {
	return &Handler{
		flow: cfg.Flow,
	}
}

// ServeHTTP handles token polling requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	common.SetJSONHeaders(w)

	if r.Method != http.MethodPost {
		common.WriteError(w, deviceflow.ErrorCodeInvalidRequest, "POST method required")
		return
	}

	if err := r.ParseForm(); err != nil {
		common.WriteError(w, deviceflow.ErrorCodeInvalidRequest, "Invalid request format")
		return
	}

	// Check for duplicate parameters per RFC 8628 section 3.4
	for key, values := range r.Form {
		if len(values) > 1 {
			common.WriteError(w, deviceflow.ErrorCodeInvalidRequest,
				"Parameters MUST NOT be included more than once: "+key)
			return
		}
	}

	// Validate required parameters
	grantType := r.Form.Get("grant_type")
	if grantType == "" {
		common.WriteError(w, deviceflow.ErrorCodeInvalidRequest,
			"The grant_type parameter is REQUIRED")
		return
	}

	if grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		common.WriteError(w, deviceflow.ErrorCodeUnsupportedGrant,
			"Only urn:ietf:params:oauth:grant-type:device_code is supported")
		return
	}

	deviceCode := r.Form.Get("device_code")
	if deviceCode == "" {
		common.WriteError(w, deviceflow.ErrorCodeInvalidRequest,
			"The device_code parameter is REQUIRED")
		return
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		common.WriteError(w, deviceflow.ErrorCodeInvalidRequest,
			"The client_id parameter is REQUIRED for public clients")
		return
	}

	// Check device code status
	token, err := h.flow.CheckDeviceCode(r.Context(), deviceCode)
	if err != nil {
		var dferr *deviceflow.DeviceFlowError
		if errors.As(err, &dferr) {
			common.WriteError(w, dferr.Code, dferr.Description)
			return
		}

		// Map standard errors to OAuth error responses per RFC 8628 section 3.5
		switch {
		case errors.Is(err, deviceflow.ErrInvalidDeviceCode):
			common.WriteError(w, deviceflow.ErrorCodeInvalidGrant,
				"The device_code is invalid or expired")
		case errors.Is(err, deviceflow.ErrExpiredCode):
			common.WriteError(w, deviceflow.ErrorCodeExpiredToken,
				"The device_code has expired")
		case errors.Is(err, deviceflow.ErrPendingAuthorization):
			common.WriteError(w, deviceflow.ErrorCodeAuthorizationPending,
				"The authorization request is still pending")
		case errors.Is(err, deviceflow.ErrSlowDown):
			common.WriteError(w, deviceflow.ErrorCodeSlowDown,
				"Polling interval must be increased by 5 seconds")
		default:
			common.WriteError(w, deviceflow.ErrorCodeServerError,
				"An unexpected error occurred processing the request")
		}
		return
	}

	// Return successful token response
	if err := json.NewEncoder(w).Encode(token); err != nil {
		common.WriteJSONError(w, err)
		return
	}
}
