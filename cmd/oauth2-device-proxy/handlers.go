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

// Device code request handler
func (s *server) handleDeviceCode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		clientID := r.Form.Get("client_id")
		if clientID == "" {
			http.Error(w, "missing client_id", http.StatusBadRequest)
			return
		}

		scope := r.Form.Get("scope")

		code, err := s.flow.RequestDeviceCode(r.Context(), clientID, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, code)
	}
}

// Device token polling handler
func (s *server) handleDeviceToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			writeError(w, "unsupported_grant_type")
			return
		}

		deviceCode := r.Form.Get("device_code")
		if deviceCode == "" {
			writeError(w, "invalid_request")
			return
		}

		token, err := s.flow.CheckDeviceCode(r.Context(), deviceCode)
		if err != nil {
			switch {
			case errors.Is(err, deviceflow.ErrInvalidDeviceCode):
				writeError(w, "invalid_grant")
			case errors.Is(err, deviceflow.ErrExpiredCode):
				writeError(w, "expired_token")
			case errors.Is(err, deviceflow.ErrPendingAuthorization):
				writeError(w, "authorization_pending")
			case errors.Is(err, deviceflow.ErrSlowDown):
				writeError(w, "slow_down")
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		writeJSON(w, token)
	}
}

// Device verification page handler
func (s *server) handleDeviceVerification() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Generate CSRF token
			token, err := s.csrf.GenerateToken(r.Context())
			if err != nil {
				s.templates.RenderError(w, templates.ErrorData{
					Title:   "System Error",
					Message: "Unable to process request. Please try again.",
				})
				return
			}

			// Render verification page
			data := templates.VerifyData{
				PrefilledCode: r.URL.Query().Get("code"),
				CSRFToken:     token,
			}
			if err := s.templates.RenderVerify(w, data); err != nil {
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}

		case http.MethodPost:
			// Verify CSRF token
			if err := s.csrf.ValidateToken(r.Context(), r.PostFormValue("csrf_token")); err != nil {
				s.templates.RenderError(w, templates.ErrorData{
					Title:   "Invalid Request",
					Message: "Please try submitting the form again.",
				})
				return
			}

			// Get and normalize user code
			code := strings.TrimSpace(r.PostFormValue("code"))
			if code == "" {
				s.templates.RenderVerify(w, templates.VerifyData{
					Error:     "Please enter a code",
					CSRFToken: r.PostFormValue("csrf_token"),
				})
				return
			}

			// Verify the code
			deviceCode, err := s.flow.VerifyUserCode(r.Context(), code)
			if err != nil {
				var data templates.VerifyData
				data.CSRFToken = r.PostFormValue("csrf_token")

				switch {
				case errors.Is(err, deviceflow.ErrInvalidUserCode):
					data.Error = "Invalid code. Please check and try again."
				case errors.Is(err, deviceflow.ErrExpiredCode):
					data.Error = "This code has expired. Please request a new code from your device."
				default:
					data.Error = "An error occurred. Please try again."
				}

				s.templates.RenderVerify(w, data)
				return
			}

			// Redirect to OAuth provider
			params := map[string]string{
				"response_type": "code",
				"client_id":     deviceCode.ClientID,
				"redirect_uri":  s.cfg.BaseURL + "/device/complete",
				"state":         deviceCode.DeviceCode,
			}
			if deviceCode.Scope != "" {
				params["scope"] = deviceCode.Scope
			}

			http.Redirect(w, r, s.buildOAuthURL(params), http.StatusFound)
		}
	}
}

// Device complete page handler
func (s *server) handleDeviceComplete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceCode := r.URL.Query().Get("state")
		if deviceCode == "" {
			s.templates.RenderError(w, templates.ErrorData{
				Title:   "Invalid Request",
				Message: "Missing or invalid state parameter",
			})
			return
		}

		authCode := r.URL.Query().Get("code")
		if authCode == "" {
			s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "No authorization code received",
			})
			return
		}

		// Exchange code for token
		token, err := s.exchangeCode(r.Context(), authCode)
		if err != nil {
			s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "Unable to complete authorization",
			})
			return
		}

		// Complete the device authorization
		if err := s.flow.CompleteAuthorization(r.Context(), deviceCode, token); err != nil {
			s.templates.RenderError(w, templates.ErrorData{
				Title:   "Authorization Failed",
				Message: "Unable to complete device authorization",
			})
			return
		}

		// Show success page
		s.templates.RenderComplete(w, templates.CompleteData{
			Message: "You have successfully authorized the device. You may now close this window.",
		})
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "error encoding response", http.StatusInternalServerError)
		return
	}
}

func writeError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	writeJSON(w, map[string]string{"error": code})
}
