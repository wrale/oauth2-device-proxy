package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

type mockFlow struct {
	checkHealthFunc func(ctx context.Context) error
}

func (m *mockFlow) CheckHealth(ctx context.Context) error {
	if m.checkHealthFunc != nil {
		return m.checkHealthFunc(ctx)
	}
	return nil
}

// Mock required Flow interface methods
func (m *mockFlow) RequestDeviceCode(ctx context.Context, clientID string, scope string) (*deviceflow.DeviceCode, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *mockFlow) GetDeviceCode(ctx context.Context, deviceCode string) (*deviceflow.DeviceCode, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *mockFlow) CheckDeviceCode(ctx context.Context, deviceCode string) (*deviceflow.TokenResponse, error) {
	return nil, deviceflow.ErrPendingAuthorization // Default per RFC 8628 section 3.5
}

func (m *mockFlow) VerifyUserCode(ctx context.Context, userCode string) (*deviceflow.DeviceCode, error) {
	return nil, errors.New("not implemented in mock")
}

func (m *mockFlow) CompleteAuthorization(ctx context.Context, deviceCode string, token *deviceflow.TokenResponse) error {
	return errors.New("not implemented in mock")
}

func TestHealthHandler(t *testing.T) {
	version := "1.0.0"

	tests := []struct {
		name      string
		checkFunc func(ctx context.Context) error
		wantCode  int
		wantBody  Response
	}{
		{
			name: "healthy system",
			checkFunc: func(ctx context.Context) error {
				return nil
			},
			wantCode: http.StatusOK,
			wantBody: Response{
				Status:  "healthy",
				Version: version,
				Details: map[string]any{
					"device_flow": map[string]any{
						"status": "healthy",
					},
				},
			},
		},
		{
			name: "device flow unhealthy",
			checkFunc: func(ctx context.Context) error {
				return errors.New("service unavailable")
			},
			wantCode: http.StatusServiceUnavailable,
			wantBody: Response{
				Status:  "unhealthy",
				Version: version,
				Details: map[string]any{
					"device_flow": map[string]any{
						"status":  "unhealthy",
						"message": "service unavailable",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := &mockFlow{checkHealthFunc: tt.checkFunc}
			handler := New(flow).WithVersion(version)

			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			// Check status code
			if got := w.Code; got != tt.wantCode {
				t.Errorf("Health handler status = %v, want %v", got, tt.wantCode)
			}

			// Check headers
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Health handler Cache-Control = %v, want no-store", got)
			}
			if got := w.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Health handler Content-Type = %v, want application/json", got)
			}

			// Check response body
			var got Response
			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if diff := cmp.Diff(tt.wantBody, got); diff != "" {
				t.Errorf("Health handler response mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
