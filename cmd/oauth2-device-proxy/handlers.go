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
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")

		resp := healthResponse{
			Status:  "ok",
			Version: Version,
		}

		// Check component health
		if err := s.checkHealth(r.Context()); err != nil {
			resp.Status = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		writeJSON(w, resp)
	}
}

// Device code request handler implements RFC 8628 section 3.2
func (s *server) handleDeviceCode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set required headers per RFC 8628 section 3.2 before any returns
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			writeError(w, "invalid_request", "POST method required (Section 3.1)")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeError(w, "invalid_request", "Invalid request format (Section 3.1)")
			return
		}

		// Check for duplicate parameters per RFC 8628 section 3.1
		for _, values := range r.Form {
			if len(values) > 1 {
				writeError(w, "invalid_request", "Parameters MUST NOT be included more than once (Section 3.1)")
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
			writeError(w, "server_error", "Error generating device code (Section 3.2)")
			return
		}

		writeJSON(w, code)
	}
}

// Device token polling handler implements RFC 8628 section 3.4
func (s *server) handleDeviceToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set required headers per RFC 8628 before any returns
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			writeError(w, "invalid_request", "POST method required (Section 3.4)")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeError(w, "invalid_request", "Invalid request format (Section 3.4)")
			return
		}

		// Check for duplicate parameters per RFC 8628
		for _, values := range r.Form {
			if len(values) > 1 {
				writeError(w, "invalid_request", "Parameters MUST NOT be included more than once (Section 3.4)")
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

		writeJSON(w, token)
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

// writeJSON writes a JSON response with appropriate headers per RFC 8628
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(v); err != nil {
		// If encoding fails, send error response per RFC 8628
		w.WriteHeader(http.StatusInternalServerError)
		// Create error response manually
		errData := map[string]string{
			"error":             "server_error",
			"error_description": "Failed to encode response",
		}
		errorBytes, _ := json.Marshal(errData)
		_, _ = w.Write(errorBytes)
	}
}

// writeError sends an RFC 8628 compliant error response
func writeError(w http.ResponseWriter, code string, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	data := map[string]string{
		"error":             code,
		"error_description": strings.TrimSpace(description),
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Create error response manually as fallback
		errData := map[string]string{
			"error":             "server_error",
			"error_description": "Failed to encode error response",
		}
		errorBytes, _ := json.Marshal(errData)
		_, _ = w.Write(errorBytes)
	}
}
