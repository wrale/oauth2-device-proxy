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
		if err := r.ParseForm(); err != nil {
			writeError(w, "invalid_request", "Invalid request format")
			return
		}

		// Check for duplicate parameters per RFC 8628 section 3.1
		for _, values := range r.Form {
			if len(values) > 1 {
				writeError(w, "invalid_request", "Parameters MUST NOT be included more than once")
				return
			}
		}

		clientID := r.Form.Get("client_id")
		if clientID == "" {
			writeError(w, "invalid_request", "client_id is REQUIRED for public clients (Section 3.1)")
			return
		}

		scope := r.Form.Get("scope")

		code, err := s.flow.RequestDeviceCode(r.Context(), clientID, scope)
		if err != nil {
			writeError(w, "server_error", err.Error())
			return
		}

		// Set required headers per RFC 8628 section 3.2
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, code)
	}
}

// Device token polling handler implements RFC 8628 section 3.4
func (s *server) handleDeviceToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeError(w, "invalid_request", "Invalid request format")
			return
		}

		// Check for duplicate parameters
		for _, values := range r.Form {
			if len(values) > 1 {
				writeError(w, "invalid_request", "Parameters MUST NOT be included more than once")
				return
			}
		}

		grantType := r.Form.Get("grant_type")
		if grantType == "" {
			writeError(w, "invalid_request", "grant_type is REQUIRED (Section 3.4)")
			return
		}

		if grantType != "urn:ietf:params:oauth:grant-type:device_code" {
			writeError(w, "unsupported_grant_type", "grant_type must be urn:ietf:params:oauth:grant-type:device_code")
			return
		}

		deviceCode := r.Form.Get("device_code")
		if deviceCode == "" {
			writeError(w, "invalid_request", "device_code is REQUIRED (Section 3.4)")
			return
		}

		token, err := s.flow.CheckDeviceCode(r.Context(), deviceCode)
		if err != nil {
			switch {
			case errors.Is(err, deviceflow.ErrInvalidDeviceCode):
				writeError(w, "invalid_grant", "Invalid or unknown device code")
			case errors.Is(err, deviceflow.ErrExpiredCode):
				writeError(w, "expired_token", "Device code has expired")
			case errors.Is(err, deviceflow.ErrPendingAuthorization):
				writeError(w, "authorization_pending", "User has not yet completed authorization")
			case errors.Is(err, deviceflow.ErrSlowDown):
				writeError(w, "slow_down", "Polling too frequently, increase polling interval by 5 seconds")
			default:
				writeError(w, "server_error", err.Error())
			}
			return
		}

		// Set required headers
		w.Header().Set("Cache-Control", "no-store")
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
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}
			return
		}

		authCode := r.URL.Query().Get("code")
		if authCode == "" {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "No authorization code received",
			}); err != nil {
				http.Error(w, "error rendering page", http.StatusInternalServerError)
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
				http.Error(w, "error rendering page", http.StatusInternalServerError)
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
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}
			return
		}

		// Complete the device authorization
		if err := s.flow.CompleteAuthorization(r.Context(), deviceCode, token); err != nil {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "Unable to complete device authorization",
			}); err != nil {
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}
			return
		}

		// Show success page
		if err := s.templates.RenderComplete(w, templates.CompleteData{
			Message: "You have successfully authorized the device. You may now close this window.",
		}); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
	}
}

// writeJSON writes a JSON response with appropriate headers
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "error encoding response", http.StatusInternalServerError)
		return
	}
}

// writeError sends an RFC 8628 compliant error response with consistent formatting
func writeError(w http.ResponseWriter, code string, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	resp := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{
		Error:            code,
		ErrorDescription: strings.TrimSpace(description),
	}
	writeJSON(w, resp)
}
