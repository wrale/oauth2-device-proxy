package token

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

type mockFlow struct {
	checkDeviceCode func(ctx context.Context, code string) (*deviceflow.TokenResponse, error)
}

func (m *mockFlow) CheckDeviceCode(ctx context.Context, code string) (*deviceflow.TokenResponse, error) {
	if m.checkDeviceCode != nil {
		return m.checkDeviceCode(ctx, code)
	}
	return nil, nil
}

func TestTokenHandler(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		params        map[string]string
		duplicateKey  string
		mockResponse  *deviceflow.TokenResponse
		mockError     error
		wantStatus    int
		wantErrorCode string
		wantErrorDesc string
		validateBody  bool
	}{
		{
			name:          "wrong method",
			method:        "GET",
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_request",
			wantErrorDesc: "POST method required",
		},
		{
			name:          "missing grant_type",
			method:        "POST",
			params:        map[string]string{},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_request",
			wantErrorDesc: "The grant_type parameter is REQUIRED",
		},
		{
			name:   "wrong grant_type",
			method: "POST",
			params: map[string]string{
				"grant_type": "invalid",
				"client_id":  "test",
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "unsupported_grant_type",
			wantErrorDesc: "Only urn:ietf:params:oauth:grant-type:device_code is supported",
		},
		{
			name:   "missing device_code",
			method: "POST",
			params: map[string]string{
				"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":  "test",
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_request",
			wantErrorDesc: "The device_code parameter is REQUIRED",
		},
		{
			name:   "missing client_id",
			method: "POST",
			params: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "test-code",
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_request",
			wantErrorDesc: "The client_id parameter is REQUIRED for public clients",
		},
		{
			name:   "duplicate parameter",
			method: "POST",
			params: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "test-code",
				"client_id":   "test",
			},
			duplicateKey:  "client_id",
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_request",
			wantErrorDesc: "Parameters MUST NOT be included more than once: client_id",
		},
		{
			name:   "successful token request",
			method: "POST",
			params: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "valid-code",
				"client_id":   "test",
			},
			mockResponse: &deviceflow.TokenResponse{
				AccessToken:  "access-123",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: "refresh-123",
				Scope:        "test",
			},
			wantStatus:   http.StatusOK,
			validateBody: true,
		},
		{
			name:   "authorization pending",
			method: "POST",
			params: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "pending-code",
				"client_id":   "test",
			},
			mockError:     deviceflow.ErrPendingAuthorization,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "authorization_pending",
			wantErrorDesc: "The authorization request is still pending",
		},
		{
			name:   "slow down",
			method: "POST",
			params: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "rate-limited",
				"client_id":   "test",
			},
			mockError:     deviceflow.ErrSlowDown,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "slow_down",
			wantErrorDesc: "Polling interval must be increased by 5 seconds",
		},
		{
			name:   "expired code",
			method: "POST",
			params: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"device_code": "expired",
				"client_id":   "test",
			},
			mockError:     deviceflow.ErrExpiredCode,
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "expired_token",
			wantErrorDesc: "The device_code has expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &mockFlow{
				checkDeviceCode: func(ctx context.Context, code string) (*deviceflow.TokenResponse, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			handler := New(flow)

			// Build request
			values := url.Values{}
			for k, v := range tt.params {
				values.Add(k, v)
			}
			if tt.duplicateKey != "" {
				values.Add(tt.duplicateKey, tt.params[tt.duplicateKey])
			}

			req := httptest.NewRequest(tt.method, "/device/token", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			// Check status
			if w.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d", w.Code, tt.wantStatus)
			}

			// Check headers
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Error("missing Cache-Control: no-store header")
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Error("missing Content-Type: application/json header")
			}

			// Parse response
			var resp map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			// Check for error response
			if tt.wantErrorCode != "" {
				if got := resp["error"].(string); got != tt.wantErrorCode {
					t.Errorf("error code = %q, want %q", got, tt.wantErrorCode)
				}
				if got := resp["error_description"].(string); got != tt.wantErrorDesc {
					t.Errorf("error description = %q, want %q", got, tt.wantErrorDesc)
				}
				return
			}

			// Validate successful response fields
			if tt.validateBody {
				required := []string{
					"access_token",
					"token_type",
					"expires_in",
				}

				for _, field := range required {
					if _, ok := resp[field]; !ok {
						t.Errorf("missing required field: %s", field)
					}
				}

				if got := resp["access_token"].(string); got != tt.mockResponse.AccessToken {
					t.Errorf("access_token = %q, want %q", got, tt.mockResponse.AccessToken)
				}
				if got := resp["token_type"].(string); got != tt.mockResponse.TokenType {
					t.Errorf("token_type = %q, want %q", got, tt.mockResponse.TokenType)
				}
				if got := int(resp["expires_in"].(float64)); got != tt.mockResponse.ExpiresIn {
					t.Errorf("expires_in = %d, want %d", got, tt.mockResponse.ExpiresIn)
				}
				if tt.mockResponse.RefreshToken != "" {
					if got := resp["refresh_token"].(string); got != tt.mockResponse.RefreshToken {
						t.Errorf("refresh_token = %q, want %q", got, tt.mockResponse.RefreshToken)
					}
				}
				if tt.mockResponse.Scope != "" {
					if got := resp["scope"].(string); got != tt.mockResponse.Scope {
						t.Errorf("scope = %q, want %q", got, tt.mockResponse.Scope)
					}
				}
			}
		})
	}
}
