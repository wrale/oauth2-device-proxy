package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	version := "1.0.0"

	tests := []struct {
		name      string
		checkFunc func() error
		wantCode  int
		wantBody  Response
	}{
		{
			name: "healthy system",
			checkFunc: func() error {
				return nil
			},
			wantCode: http.StatusOK,
			wantBody: Response{
				Status:  "ok",
				Version: version,
			},
		},
		{
			name: "degraded system",
			checkFunc: func() error {
				return errors.New("service unavailable")
			},
			wantCode: http.StatusServiceUnavailable,
			wantBody: Response{
				Status:  "degraded",
				Version: version,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := New(version, tt.checkFunc)

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

			if got != tt.wantBody {
				t.Errorf("Health handler response = %v, want %v", got, tt.wantBody)
			}
		})
	}
}
