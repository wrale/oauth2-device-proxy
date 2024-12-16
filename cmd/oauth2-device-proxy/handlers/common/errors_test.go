package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteError(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		description string
		wantStatus  int
		wantHeaders map[string]string
	}{
		{
			name:        "basic error",
			code:        "invalid_request",
			description: "Missing required parameter",
			wantStatus:  http.StatusBadRequest,
			wantHeaders: map[string]string{
				"Cache-Control": "no-store",
				"Content-Type":  "application/json",
			},
		},
		{
			name:        "error without description",
			code:        "access_denied",
			description: "",
			wantStatus:  http.StatusBadRequest,
			wantHeaders: map[string]string{
				"Cache-Control": "no-store",
				"Content-Type":  "application/json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteError(w, tt.code, tt.description)

			// Check status code
			if got := w.Code; got != tt.wantStatus {
				t.Errorf("WriteError() status = %v, want %v", got, tt.wantStatus)
			}

			// Check headers
			for k, v := range tt.wantHeaders {
				if got := w.Header().Get(k); got != v {
					t.Errorf("WriteError() header[%s] = %v, want %v", k, got, v)
				}
			}

			// Check response body
			var resp ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if resp.Error != tt.code {
				t.Errorf("WriteError() error = %v, want %v", resp.Error, tt.code)
			}
			if resp.ErrorDescription != tt.description {
				t.Errorf("WriteError() description = %v, want %v",
					resp.ErrorDescription, tt.description)
			}
		})
	}
}

func TestWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSONError(w, json.ErrSyntaxError([]byte(""), 0))

	// Check status and headers
	if w.Code != http.StatusInternalServerError {
		t.Errorf("WriteJSONError() status = %v, want %v", w.Code,
			http.StatusInternalServerError)
	}

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("WriteJSONError() Cache-Control = %v, want no-store", got)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("WriteJSONError() Content-Type = %v, want application/json", got)
	}

	// Check response structure
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Error != "server_error" {
		t.Errorf("WriteJSONError() error = %v, want server_error", resp.Error)
	}
	if resp.ErrorDescription != "Failed to encode response" {
		t.Errorf("WriteJSONError() description = %v, want 'Failed to encode response'",
			resp.ErrorDescription)
	}
}

func TestSetJSONHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	SetJSONHeaders(w)

	wantHeaders := map[string]string{
		"Cache-Control": "no-store",
		"Content-Type":  "application/json",
	}

	for k, v := range wantHeaders {
		if got := w.Header().Get(k); got != v {
			t.Errorf("SetJSONHeaders() header[%s] = %v, want %v", k, got, v)
		}
	}
}
