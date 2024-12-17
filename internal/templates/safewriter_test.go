package templates

import (
	"net/http"
	"testing"
)

func TestSafeWriter_WriteHeader(t *testing.T) {
	tests := []struct {
		name            string
		setupWriter     func(*SafeWriter)
		wantStatus      int
		wantContentType string
		wantWriteCount  int
	}{
		{
			name: "sets default status and content type",
			setupWriter: func(sw *SafeWriter) {
				sw.WriteHeader(http.StatusOK)
			},
			wantStatus:      http.StatusOK,
			wantContentType: "text/html; charset=utf-8",
			wantWriteCount:  0,
		},
		{
			name: "respects custom status code",
			setupWriter: func(sw *SafeWriter) {
				sw.SetStatusCode(http.StatusBadRequest)
				sw.WriteHeader(http.StatusBadRequest)
			},
			wantStatus:      http.StatusBadRequest,
			wantContentType: "text/html; charset=utf-8",
			wantWriteCount:  0,
		},
		{
			name: "only writes headers once",
			setupWriter: func(sw *SafeWriter) {
				sw.WriteHeader(http.StatusOK)
				sw.WriteHeader(http.StatusBadRequest)
			},
			wantStatus:      http.StatusOK,
			wantContentType: "text/html; charset=utf-8",
			wantWriteCount:  0,
		},
	}

	templates := setupTemplates(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockResponseWriter()
			sw := templates.NewSafeWriter(mock)

			tt.setupWriter(sw)

			if mock.statusCode != tt.wantStatus {
				t.Errorf("status = %v, want %v", mock.statusCode, tt.wantStatus)
			}
			if got := mock.headers.Get("Content-Type"); got != tt.wantContentType {
				t.Errorf("Content-Type = %v, want %v", got, tt.wantContentType)
			}
			if mock.writeCount != tt.wantWriteCount {
				t.Errorf("writeCount = %v, want %v", mock.writeCount, tt.wantWriteCount)
			}
		})
	}
}

func TestSafeWriter_Write(t *testing.T) {
	tests := []struct {
		name            string
		writes          []string
		setStatusCode   int
		wantStatus      int
		wantContentType string
		wantWriteCount  int
		wantContent     string
	}{
		{
			name:            "single write with default status",
			writes:          []string{"hello world"},
			wantStatus:      http.StatusOK,
			wantContentType: "text/html; charset=utf-8",
			wantWriteCount:  1,
			wantContent:     "hello world",
		},
		{
			name:            "multiple writes",
			writes:          []string{"hello", " ", "world"},
			wantStatus:      http.StatusOK,
			wantContentType: "text/html; charset=utf-8",
			wantWriteCount:  3,
			wantContent:     "hello world",
		},
		{
			name:            "write with custom status",
			writes:          []string{"error message"},
			setStatusCode:   http.StatusBadRequest,
			wantStatus:      http.StatusBadRequest,
			wantContentType: "text/html; charset=utf-8",
			wantWriteCount:  1,
			wantContent:     "error message",
		},
	}

	templates := setupTemplates(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockResponseWriter()
			sw := templates.NewSafeWriter(mock)

			if tt.setStatusCode != 0 {
				sw.SetStatusCode(tt.setStatusCode)
			}

			for _, write := range tt.writes {
				n, err := sw.Write([]byte(write))
				if err != nil {
					t.Fatalf("Write() error = %v", err)
				}
				if n != len(write) {
					t.Errorf("Write() wrote %d bytes, want %d", n, len(write))
				}
			}

			if mock.statusCode != tt.wantStatus {
				t.Errorf("status = %v, want %v", mock.statusCode, tt.wantStatus)
			}
			if got := mock.headers.Get("Content-Type"); got != tt.wantContentType {
				t.Errorf("Content-Type = %v, want %v", got, tt.wantContentType)
			}
			if mock.writeCount != tt.wantWriteCount {
				t.Errorf("writeCount = %v, want %v", mock.writeCount, tt.wantWriteCount)
			}
			if got := mock.Written(); got != tt.wantContent {
				t.Errorf("content = %q, want %q", got, tt.wantContent)
			}
		})
	}
}

func TestSafeWriter_Written(t *testing.T) {
	templates := setupTemplates(t)
	mock := newMockResponseWriter()
	sw := templates.NewSafeWriter(mock)

	if sw.Written() {
		t.Error("new SafeWriter reports as written")
	}

	if _, err := sw.Write([]byte("test")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if !sw.Written() {
		t.Error("SafeWriter.Written() = false after Write")
	}
}
