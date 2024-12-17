package device

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wrale/oauth2-device-proxy/cmd/oauth2-device-proxy/handlers/common/test"
	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

func TestDeviceCodeHandler(t *testing.T) {
	validExpiry := time.Now().Add(5 * time.Minute)

	tests := []struct {
		name          string
		method        string
		params        map[string]string
		duplicateKey  string
		mockResponse  *deviceflow.DeviceCode
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
			name:          "missing client_id",
			method:        "POST",
			params:        map[string]string{},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_request",
			wantErrorDesc: "The client_id parameter is REQUIRED",
		},
		{
			name:          "duplicate parameter",
			method:        "POST",
			params:        map[string]string{"client_id": "test"},
			duplicateKey:  "client_id",
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "invalid_request",
			wantErrorDesc: "Parameters MUST NOT be included more than once: client_id",
		},
		{
			name:   "successful request",
			method: "POST",
			params: map[string]string{
				"client_id": "test-client",
				"scope":     "test",
			},
			mockResponse: &deviceflow.DeviceCode{
				DeviceCode:              "device-123",
				UserCode:                "USER-123",
				VerificationURI:         "https://example.com/verify",
				VerificationURIComplete: "https://example.com/verify?code=USER-123",
				ExpiresAt:               validExpiry,
				Interval:                5,
			},
			wantStatus:   http.StatusOK,
			validateBody: true,
		},
		{
			name:   "flow error",
			method: "POST",
			params: map[string]string{
				"client_id": "test-client",
			},
			mockError: &deviceflow.DeviceFlowError{
				Code:        "server_error",
				Description: "Internal error",
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: "server_error",
			wantErrorDesc: "Internal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock using common test mock implementation
			flow := &test.MockFlow{
				RequestDeviceCodeFunc: func(ctx context.Context, clientID string, scope string) (*deviceflow.DeviceCode, error) {
					if tt.mockError != nil {
						return nil, tt.mockError
					}
					return tt.mockResponse, nil
				},
			}

			// Create handler
			handler := New(flow)

			// Build request
			values := url.Values{}
			for k, v := range tt.params {
				values.Add(k, v)
			}
			if tt.duplicateKey != "" {
				values.Add(tt.duplicateKey, tt.params[tt.duplicateKey])
			}

			req := httptest.NewRequest(tt.method, "/device/code", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(w, req)

			// Verify status code
			if w.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d", w.Code, tt.wantStatus)
			}

			// Verify headers
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Error("missing Cache-Control: no-store header")
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Error("missing Content-Type: application/json header")
			}

			// Parse response body
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

			// Validate successful response format per RFC 8628 section 3.2
			if tt.validateBody {
				required := []string{
					"device_code",
					"user_code",
					"verification_uri",
					"expires_in",
					"interval",
				}

				for _, field := range required {
					if _, ok := resp[field]; !ok {
						t.Errorf("missing required field: %s", field)
					}
				}

				if got := resp["device_code"].(string); got != tt.mockResponse.DeviceCode {
					t.Errorf("device_code = %q, want %q", got, tt.mockResponse.DeviceCode)
				}
				if got := resp["user_code"].(string); got != tt.mockResponse.UserCode {
					t.Errorf("user_code = %q, want %q", got, tt.mockResponse.UserCode)
				}
				if got := resp["verification_uri"].(string); got != tt.mockResponse.VerificationURI {
					t.Errorf("verification_uri = %q, want %q", got, tt.mockResponse.VerificationURI)
				}
				if got, ok := resp["verification_uri_complete"].(string); ok {
					if got != tt.mockResponse.VerificationURIComplete {
						t.Errorf("verification_uri_complete = %q, want %q", got, tt.mockResponse.VerificationURIComplete)
					}
				}

				// Check expires_in is reasonable per RFC 8628 section 3.2
				if got := int(resp["expires_in"].(float64)); got <= 0 {
					t.Error("expires_in must be positive")
				}

				if got := int(resp["interval"].(float64)); got != tt.mockResponse.Interval {
					t.Errorf("interval = %d, want %d", got, tt.mockResponse.Interval)
				}
			}
		})
	}
}
