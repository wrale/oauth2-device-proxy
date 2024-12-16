package device

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/wrale/oauth2-device-proxy/cmd/oauth2-device-proxy/handlers/common"
	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

// CodeResponse represents the device code response per RFC 8628 section 3.2
type CodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Handler processes device code requests per RFC 8628 section 3.2
type Handler struct {
	flow *deviceflow.Flow
}

// New creates a new device code request handler
func New(flow *deviceflow.Flow) *Handler {
	return &Handler{
		flow: flow,
	}
}

// ServeHTTP handles device code requests
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

	// Check for duplicate parameters per RFC 8628 section 3.1
	for key, values := range r.Form {
		if len(values) > 1 {
			common.WriteError(w, deviceflow.ErrorCodeInvalidRequest, "Parameters MUST NOT be included more than once: "+key)
			return
		}
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		common.WriteError(w, deviceflow.ErrorCodeInvalidRequest, "The client_id parameter is REQUIRED")
		return
	}

	scope := r.Form.Get("scope")
	code, err := h.flow.RequestDeviceCode(r.Context(), clientID, scope)
	if err != nil {
		var dferr *deviceflow.DeviceFlowError
		if errors.As(err, &dferr) {
			common.WriteError(w, dferr.Code, dferr.Description)
			return
		}
		// Handle non-DeviceFlowErrors with a default error
		common.WriteError(w, deviceflow.ErrorCodeServerError, "Failed to generate device code")
		return
	}

	// Ensure expires_in is positive and calculated from response time
	expiresIn := int(time.Until(code.ExpiresAt).Seconds())
	if expiresIn <= 0 {
		common.WriteError(w, deviceflow.ErrorCodeInvalidRequest, "Invalid expiration time")
		return
	}

	// Build RFC 8628 compliant response
	response := CodeResponse{
		DeviceCode:              code.DeviceCode,
		UserCode:                code.UserCode,
		VerificationURI:         code.VerificationURI,
		VerificationURIComplete: code.VerificationURIComplete,
		ExpiresIn:               expiresIn,
		Interval:                code.Interval,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		common.WriteJSONError(w, err)
		return
	}
}
