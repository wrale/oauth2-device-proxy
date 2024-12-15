// Package main implements the OAuth 2.0 Device Flow Proxy server
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jmdots/oauth2-device-proxy/internal/deviceflow"
	"github.com/jmdots/oauth2-device-proxy/internal/templates"
)

// Health check handler
func (s *server) handleHealth() http.HandlerFunc {
	type healthResponse struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Always set required headers per RFC 8628
		setJSONHeaders(w)

		resp := healthResponse{
			Status:  "ok",
			Version: Version,
		}

		// Check component health
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
		// Set required headers per RFC 8628 section 3.2 before any returns
		setJSONHeaders(w)

		if r.Method != http.MethodPost {
			writeError(w, "invalid_request", "POST method required (Section 3.1)")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeError(w, "invalid_request", "Invalid request format (Section 3.1)")
			return
		}

		// Check for duplicate parameters per RFC 8628 section 3.1
		for key, values := range r.Form {
			if len(values) > 1 {
				writeError(w, "invalid_request", "Parameters MUST NOT be included more than once (Section 3.1): "+key)
				return
			}
		}

		clientID := r.Form.Get("client_id")
		if clientID == "" {
			writeError(w, "invalid_request", "The client_id parameter is REQUIRED (Section 3.1)")
			return
		}

		scope := r.Form.Get("scope")
		code, err := s.flow.RequestDeviceCode(r.Context(), clientID, scope)
		if err != nil {
			if errors.Is(err, deviceflow.ErrInvalidDeviceCode) {
				writeError(w, "invalid_request", "Invalid device code format (Section 3.2)")
			} else if errors.Is(err, deviceflow.ErrInvalidUserCode) {
				writeError(w, "invalid_request", "Invalid user code format (Section 6.1)")
			} else {
				writeError(w, "server_error", "Failed to generate device code (Section 3.2)")
			}
			return
		}

		// Ensure compliant response format per RFC 8628 section 3.2
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
			ExpiresIn:               code.ExpiresIn,
			Interval:                code.Interval,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			handleJSONError(w, err)
		}
	}
}

// Device token polling handler implements RFC 8628 section 3.4
func (s *server) handleDeviceToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set required headers per RFC 8628 before any returns
		setJSONHeaders(w)

		if r.Method != http.MethodPost {
			writeError(w, "invalid_request", "POST method required (Section 3.4)")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeError(w, "invalid_request", "Invalid request format (Section 3.4)")
			return
		}

		// Check for duplicate parameters per RFC 8628
		for key, values := range r.Form {
			if len(values) > 1 {
				writeError(w, "invalid_request", "Parameters MUST NOT be included more than once (Section 3.4): "+key)
				return
			}
		}

		grantType := r.Form.Get("grant_type")
		if grantType == "" {
			writeError(w, "invalid_request", "The grant_type parameter is REQUIRED (Section 3.4)")
			return
		}

		if grantType != "urn:ietf:params:oauth:grant-type:device_code" {
			writeError(w, "unsupported_grant_type", "Only urn:ietf:params:oauth:grant-type:device_code is supported (Section 3.4)")
			return
		}

		deviceCode := r.Form.Get("device_code")
		if deviceCode == "" {
			writeError(w, "invalid_request", "The device_code parameter is REQUIRED (Section 3.4)")
			return
		}

		token, err := s.flow.CheckDeviceCode(r.Context(), deviceCode)
		if err != nil {
			switch {
			case errors.Is(err, deviceflow.ErrInvalidDeviceCode):
				writeError(w, "invalid_grant", "The device_code is invalid or expired (Section 3.5)")
			case errors.Is(err, deviceflow.ErrExpiredCode):
				writeError(w, "expired_token", "The device_code has expired (Section 3.5)")
			case errors.Is(err, deviceflow.ErrPendingAuthorization):
				writeError(w, "authorization_pending", "The authorization request is still pending (Section 3.5)")
			case errors.Is(err, deviceflow.ErrSlowDown):
				writeError(w, "slow_down", "Please slow down polling by increasing your interval by 5 seconds (Section 3.5)")
			default:
				writeError(w, "server_error", "An unexpected error occurred processing the request")
			}
			return
		}

		if err := json.NewEncoder(w).Encode(token); err != nil {
			handleJSONError(w, err)
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

// handleJSONError handles JSON encoding errors with a proper error response
func handleJSONError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	errResponse := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{
		Error:            "server_error",
		ErrorDescription: "Failed to encode response",
	}
	// Create error response manually as fallback
	errorBytes, _ := json.Marshal(errResponse)
	if _, err := w.Write(errorBytes); err != nil {
		// At this point, we've exhausted our options for sending an error response
		// Log the error if we have a logger, but continue since we can't recover
		// TODO: Add logging once we have a logger configured
	}
}

// writeError sends an RFC 8628 compliant error response
func writeError(w http.ResponseWriter, code string, description string) {
	w.WriteHeader(http.StatusBadRequest)

	response := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}{
		Error:            code,
		ErrorDescription: strings.TrimSpace(description),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		handleJSONError(w, err)
	}
}
