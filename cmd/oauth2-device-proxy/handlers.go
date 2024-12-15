// Package main implements the OAuth 2.0 Device Flow Proxy server
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

// Health check handler
func (s *server) handleHealth() http.HandlerFunc {
	type healthResponse struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		setJSONHeaders(w)

		resp := healthResponse{
			Status:  "ok",
			Version: Version,
		}

		if err := s.checkHealth(r.Context()); err != nil {
			resp.Status = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			handleJSONError(w, err)
		}
	}
}

// Device code request handler implements RFC 8628 section 3.2
func (s *server) handleDeviceCode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setJSONHeaders(w)

		if r.Method != http.MethodPost {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "POST method required")
			return
		}

		if err := r.ParseForm(); err != nil {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "Invalid request format")
			return
		}

		// Check for duplicate parameters per RFC 8628 section 3.1
		for key, values := range r.Form {
			if len(values) > 1 {
				handleError(w, deviceflow.ErrorCodeInvalidRequest, "Parameters MUST NOT be included more than once: "+key)
				return
			}
		}

		clientID := r.Form.Get("client_id")
		if clientID == "" {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "The client_id parameter is REQUIRED")
			return
		}

		scope := r.Form.Get("scope")
		code, err := s.flow.RequestDeviceCode(r.Context(), clientID, scope)
		if err != nil {
			var (
				dferr      *deviceflow.DeviceFlowError
				errMessage string
			)
			if errors.As(err, &dferr) {
				handleError(w, dferr.Code, dferr.Description)
				return
			}
			// Handle non-DeviceFlowErrors with a default error
			handleError(w, deviceflow.ErrorCodeServerError, "Failed to generate device code")
			return
		}

		// Ensure expires_in is positive and calculated from response time
		expiresIn := int(time.Until(code.ExpiresAt).Seconds())
		if expiresIn <= 0 {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "Invalid expiration time")
			return
		}

		response := struct {
			DeviceCode              string `json:"device_code"`
			UserCode                string `json:"user_code"`
			VerificationURI         string `json:"verification_uri"`
			VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
			ExpiresIn               int    `json:"expires_in"`
			Interval                int    `json:"interval"`
		}{
			DeviceCode:              code.DeviceCode,
			UserCode:                code.UserCode,
			VerificationURI:         code.VerificationURI,
			VerificationURIComplete: code.VerificationURIComplete,
			ExpiresIn:               expiresIn,
			Interval:                code.Interval,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			handleJSONError(w, err)
			return
		}
	}
}

// Device token polling handler implements RFC 8628 section 3.4
func (s *server) handleDeviceToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setJSONHeaders(w)

		if r.Method != http.MethodPost {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "POST method required")
			return
		}

		if err := r.ParseForm(); err != nil {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "Invalid request format")
			return
		}

		// Check for duplicate parameters per RFC 8628 section 3.4
		for key, values := range r.Form {
			if len(values) > 1 {
				handleError(w, deviceflow.ErrorCodeInvalidRequest, "Parameters MUST NOT be included more than once: "+key)
				return
			}
		}

		grantType := r.Form.Get("grant_type")
		if grantType == "" {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "The grant_type parameter is REQUIRED")
			return
		}

		if grantType != "urn:ietf:params:oauth:grant-type:device_code" {
			handleError(w, deviceflow.ErrorCodeUnsupportedGrant, "Only urn:ietf:params:oauth:grant-type:device_code is supported")
			return
		}

		deviceCode := r.Form.Get("device_code")
		if deviceCode == "" {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "The device_code parameter is REQUIRED")
			return
		}

		clientID := r.Form.Get("client_id")
		if clientID == "" {
			handleError(w, deviceflow.ErrorCodeInvalidRequest, "The client_id parameter is REQUIRED for public clients")
			return
		}

		token, err := s.flow.CheckDeviceCode(r.Context(), deviceCode)
		if err != nil {
			var dferr *deviceflow.DeviceFlowError
			if errors.As(err, &dferr) {
				handleError(w, dferr.Code, dferr.Description)
				return
			}

			// If not a known error type, convert it based on the error value
			switch {
			case errors.Is(err, deviceflow.ErrInvalidDeviceCode):
				handleError(w, deviceflow.ErrorCodeInvalidGrant, "The device_code is invalid or expired")
			case errors.Is(err, deviceflow.ErrExpiredCode):
				handleError(w, deviceflow.ErrorCodeExpiredToken, "The device_code has expired")
			case errors.Is(err, deviceflow.ErrPendingAuthorization):
				handleError(w, deviceflow.ErrorCodeAuthorizationPending, "The authorization request is still pending")
			case errors.Is(err, deviceflow.ErrSlowDown):
				handleError(w, deviceflow.ErrorCodeSlowDown, "Polling interval must be increased by 5 seconds")
			default:
				handleError(w, deviceflow.ErrorCodeServerError, "An unexpected error occurred processing the request")
			}
			return
		}

		if err := json.NewEncoder(w).Encode(token); err != nil {
			handleJSONError(w, err)
			return
		}
	}
}

// Device complete page handler for OAuth callback
func (s *server) handleDeviceComplete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceCode := r.URL.Query().Get("state")
		if deviceCode == "" {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Invalid Request",
				Message: "Missing or invalid state parameter",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		authCode := r.URL.Query().Get("code")
		if authCode == "" {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "No authorization code received",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Load device code details to preserve scope
		dCode, err := s.flow.GetDeviceCode(r.Context(), deviceCode)
		if err != nil {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "Device code verification failed",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Exchange code for token
		token, err := s.exchangeCode(r.Context(), authCode, dCode)
		if err != nil {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "Unable to complete authorization",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Complete the device authorization
		if err := s.flow.CompleteAuthorization(r.Context(), deviceCode, token); err != nil {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "Unable to complete device authorization",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		// Show success page
		if err := s.templates.RenderComplete(w, templates.CompleteData{
			Message: "You have successfully authorized the device. You may now close this window.",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// setJSONHeaders sets required headers for JSON responses per RFC 8628
func setJSONHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
}

// handleError sends a standardized error response per RFC 8628
func handleError(w http.ResponseWriter, code string, description string) {
	// First set required headers per RFC 8628
	setJSONHeaders(w)

	response := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{
		Error:            code,
		ErrorDescription: strings.TrimSpace(description),
	}

	// Now set status code and write response
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleJSONError(w, err)
		return
	}
}

// handleJSONError is called when JSON encoding itself fails
func handleJSONError(w http.ResponseWriter, err error) {
	// Headers must be set here since they weren't set by caller due to error
	setJSONHeaders(w)
	w.WriteHeader(http.StatusInternalServerError)

	// Create error response manually since JSON encoding failed
	errResponse := []byte(`{"error":"server_error","error_description":"Failed to encode response"}`)
	if _, writeErr := w.Write(errResponse); writeErr != nil {
		// At this point all we can do is log the compound error when we have logging
		return
	}
}
