package verify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/wrale/oauth2-device-proxy/internal/csrf"
	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

type mockFlow struct {
	verifyUserCode        func(ctx context.Context, code string) (*deviceflow.DeviceCode, error)
	getDeviceCode         func(ctx context.Context, code string) (*deviceflow.DeviceCode, error)
	completeAuthorization func(ctx context.Context, code string, token *deviceflow.TokenResponse) error
}

func (m *mockFlow) VerifyUserCode(ctx context.Context, code string) (*deviceflow.DeviceCode, error) {
	if m.verifyUserCode != nil {
		return m.verifyUserCode(ctx, code)
	}
	return nil, nil
}

func (m *mockFlow) GetDeviceCode(ctx context.Context, code string) (*deviceflow.DeviceCode, error) {
	if m.getDeviceCode != nil {
		return m.getDeviceCode(ctx, code)
	}
	return nil, nil
}

func (m *mockFlow) CompleteAuthorization(ctx context.Context, code string, token *deviceflow.TokenResponse) error {
	if m.completeAuthorization != nil {
		return m.completeAuthorization(ctx, code, token)
	}
	return nil
}

type mockCSRF struct {
	generateToken func(ctx context.Context) (string, error)
	validateToken func(ctx context.Context, token string) error
}

func (m *mockCSRF) GenerateToken(ctx context.Context) (string, error) {
	if m.generateToken != nil {
		return m.generateToken(ctx)
	}
	return "mock-csrf-token", nil
}

func (m *mockCSRF) ValidateToken(ctx context.Context, token string) error {
	if m.validateToken != nil {
		return m.validateToken(ctx, token)
	}
	return nil
}

type mockTemplates struct {
	renderVerify   func(w http.ResponseWriter, data templates.VerifyData) error
	renderError    func(w http.ResponseWriter, data templates.ErrorData) error
	renderComplete func(w http.ResponseWriter, data templates.CompleteData) error
	generateQRCode func(uri string) (string, error)
}

func (m *mockTemplates) RenderVerify(w http.ResponseWriter, data templates.VerifyData) error {
	if m.renderVerify != nil {
		return m.renderVerify(w, data)
	}
	return nil
}

func (m *mockTemplates) RenderError(w http.ResponseWriter, data templates.ErrorData) error {
	if m.renderError != nil {
		return m.renderError(w, data)
	}
	return nil
}

func (m *mockTemplates) RenderComplete(w http.ResponseWriter, data templates.CompleteData) error {
	if m.renderComplete != nil {
		return m.renderComplete(w, data)
	}
	return nil
}

func (m *mockTemplates) GenerateQRCode(uri string) (string, error) {
	if m.generateQRCode != nil {
		return m.generateQRCode(uri)
	}
	return "<svg>mock-qr-code</svg>", nil
}

func TestVerifyHandler_HandleForm(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		csrfError      error
		qrError        error
		wantStatusCode int
		wantQRCode     bool
		wantError      bool
	}{
		{
			name:           "success with code",
			code:           "USER-123",
			wantStatusCode: http.StatusOK,
			wantQRCode:     true,
		},
		{
			name:           "success without code",
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "csrf error",
			csrfError:      errors.New("csrf error"),
			wantStatusCode: http.StatusInternalServerError,
			wantError:      true,
		},
		{
			name:           "qr generation error",
			code:           "USER-123",
			qrError:        errors.New("qr error"),
			wantStatusCode: http.StatusOK,
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var renderedVerify, renderedError bool
			var gotQRCode bool

			tmpls := &mockTemplates{
				renderVerify: func(w http.ResponseWriter, data templates.VerifyData) error {
					renderedVerify = true
					gotQRCode = data.VerificationQRCodeSVG != ""
					return nil
				},
				renderError: func(w http.ResponseWriter, data templates.ErrorData) error {
					renderedError = true
					return nil
				},
				generateQRCode: func(uri string) (string, error) {
					if tt.qrError != nil {
						return "", tt.qrError
					}
					return "<svg>test-qr</svg>", nil
				},
			}

			csrf := &mockCSRF{
				generateToken: func(ctx context.Context) (string, error) {
					if tt.csrfError != nil {
						return "", tt.csrfError
					}
					return "test-token", nil
				},
			}

			handler := New(Config{
				Flow:      &mockFlow{},
				Templates: tmpls,
				CSRF:      csrf,
				BaseURL:   "https://example.com",
			})

			req := httptest.NewRequest(http.MethodGet, "/verify", nil)
			if tt.code != "" {
				q := req.URL.Query()
				q.Add("code", tt.code)
				req.URL.RawQuery = q.Encode()
			}

			w := httptest.NewRecorder()
			handler.HandleForm(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.wantStatusCode)
			}

			if tt.wantError && !renderedError {
				t.Error("expected error to be rendered")
			}

			if !tt.wantError && !renderedVerify {
				t.Error("expected verify form to be rendered")
			}

			if tt.wantQRCode && !gotQRCode {
				t.Error("expected QR code to be included")
			}
		})
	}
}

func TestVerifyHandler_HandleSubmit(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		csrfToken      string
		validateError  error
		verifyError    error
		mockDeviceCode *deviceflow.DeviceCode
		wantStatusCode int
		wantRedirect   bool
		wantError      bool
	}{
		{
			name:           "successful verification",
			code:           "VALID-123",
			csrfToken:      "valid-token",
			mockDeviceCode: &deviceflow.DeviceCode{DeviceCode: "device-123", ClientID: "test"},
			wantStatusCode: http.StatusFound,
			wantRedirect:   true,
		},
		{
			name:           "missing code",
			csrfToken:      "valid-token",
			wantStatusCode: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "csrf validation error",
			code:           "VALID-123",
			csrfToken:      "invalid-token",
			validateError:  csrf.ErrInvalidToken,
			wantStatusCode: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "verification error",
			code:           "INVALID-123",
			csrfToken:      "valid-token",
			verifyError:    deviceflow.ErrInvalidUserCode,
			wantStatusCode: http.StatusOK,
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var renderedVerify, renderedError bool
			var redirectURL string

			csrf := &mockCSRF{
				validateToken: func(ctx context.Context, token string) error {
					if tt.validateError != nil {
						return tt.validateError
					}
					if token != tt.csrfToken {
						return errors.New("invalid token")
					}
					return nil
				},
			}

			flow := &mockFlow{
				verifyUserCode: func(ctx context.Context, code string) (*deviceflow.DeviceCode, error) {
					if tt.verifyError != nil {
						return nil, tt.verifyError
					}
					return tt.mockDeviceCode, nil
				},
			}

			tmpls := &mockTemplates{
				renderVerify: func(w http.ResponseWriter, data templates.VerifyData) error {
					renderedVerify = true
					return nil
				},
				renderError: func(w http.ResponseWriter, data templates.ErrorData) error {
					renderedError = true
					return nil
				},
			}

			handler := New(Config{
				Flow:      flow,
				Templates: tmpls,
				CSRF:      csrf,
				OAuth:     &oauth2.Config{},
				BaseURL:   "https://example.com",
			})

			values := url.Values{}
			if tt.code != "" {
				values.Set("code", tt.code)
			}
			if tt.csrfToken != "" {
				values.Set("csrf_token", tt.csrfToken)
			}

			req := httptest.NewRequest(http.MethodPost, "/verify", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			handler.HandleSubmit(w, req)

			if w.Code != tt.wantStatusCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.wantStatusCode)
			}

			if tt.wantRedirect {
				if w.Code != http.StatusFound {
					t.Errorf("expected redirect, got status %d", w.Code)
				}
				if loc := w.Header().Get("Location"); loc == "" {
					t.Error("missing Location header for redirect")
				}
			}

			if tt.wantError && !renderedError {
				t.Error("expected error to be rendered")
			}

			if !tt.wantError && !tt.wantRedirect && !renderedVerify {
				t.Error("expected verify form to be rendered")
			}
		})
	}
}