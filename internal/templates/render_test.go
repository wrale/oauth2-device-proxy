package templates

import (
	"errors"
	"html/template"
	"net/http"
	"strings"
	"testing"
)

func TestRenderVerify(t *testing.T) {
	tests := []struct {
		name         string
		data         VerifyData
		wantContains []string
		wantStatus   int
	}{
		{
			name: "renders empty form",
			data: VerifyData{
				CSRFToken: "token123",
			},
			wantContains: []string{
				`value="token123"`,
				"Enter Device Code",
				"placeholder=\"XXXX-XXXX\"",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "renders with prefilled code",
			data: VerifyData{
				PrefilledCode: "ABCD-1234",
				CSRFToken:     "token123",
			},
			wantContains: []string{
				`value="ABCD-1234"`,
				`value="token123"`,
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "renders with error message",
			data: VerifyData{
				Error:     "Invalid code",
				CSRFToken: "token123",
			},
			wantContains: []string{
				"Invalid code",
				`class="error"`,
			},
			wantStatus: http.StatusOK,
		},
	}

	templates := setupTemplates(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockResponseWriter()
			err := templates.RenderVerify(mock, tt.data)
			if err != nil {
				t.Fatalf("RenderVerify() error = %v", err)
			}

			if mock.statusCode != tt.wantStatus {
				t.Errorf("status = %v, want %v", mock.statusCode, tt.wantStatus)
			}

			if !mock.Contains(tt.wantContains...) {
				t.Errorf("response missing required content.\ngot: %s", mock.Written())
			}
		})
	}
}

func TestRenderComplete(t *testing.T) {
	tests := []struct {
		name         string
		data         CompleteData
		wantContains []string
		wantStatus   int
	}{
		{
			name: "renders with default message",
			data: CompleteData{},
			wantContains: []string{
				"Device Authorized",
				"successfully authorized",
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "renders with custom message",
			data: CompleteData{
				Message: "Custom success message",
			},
			wantContains: []string{
				"Device Authorized",
				"Custom success message",
			},
			wantStatus: http.StatusOK,
		},
	}

	templates := setupTemplates(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockResponseWriter()
			err := templates.RenderComplete(mock, tt.data)
			if err != nil {
				t.Fatalf("RenderComplete() error = %v", err)
			}

			if mock.statusCode != tt.wantStatus {
				t.Errorf("status = %v, want %v", mock.statusCode, tt.wantStatus)
			}

			if !mock.Contains(tt.wantContains...) {
				t.Errorf("response missing required content.\ngot: %s", mock.Written())
			}
		})
	}
}

func TestRenderError(t *testing.T) {
	tests := []struct {
		name         string
		data         ErrorData
		wantContains []string
		wantStatus   int
	}{
		{
			name: "renders error page",
			data: ErrorData{
				Title:   "Test Error",
				Message: "Something went wrong",
			},
			wantContains: []string{
				"Test Error",
				"Something went wrong",
				"Try Again",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	templates := setupTemplates(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockResponseWriter()
			err := templates.RenderError(mock, tt.data)
			if err != nil {
				t.Fatalf("RenderError() error = %v", err)
			}

			if mock.statusCode != tt.wantStatus {
				t.Errorf("status = %v, want %v", mock.statusCode, tt.wantStatus)
			}

			if !mock.Contains(tt.wantContains...) {
				t.Errorf("response missing required content.\ngot: %s", mock.Written())
			}
		})
	}
}

func TestRenderToString(t *testing.T) {
	templates := setupTemplates(t)

	tests := []struct {
		name    string
		tmpl    *template.Template
		data    interface{}
		want    []string
		wantErr bool
	}{
		{
			name: "verify template to string",
			tmpl: templates.verify,
			data: VerifyData{
				PrefilledCode: "TEST-CODE",
				CSRFToken:     "test-token",
			},
			want: []string{
				"TEST-CODE",
				"test-token",
				"Enter Device Code",
			},
			wantErr: false,
		},
		{
			name: "error template to string",
			tmpl: templates.error,
			data: ErrorData{
				Title:   "Error Title",
				Message: "Error Message",
			},
			want: []string{
				"Error Title",
				"Error Message",
				"Try Again",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := templates.RenderToString(tt.tmpl, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("RenderToString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("RenderToString() missing %q in output:\n%s", want, got)
				}
			}
		})
	}
}

func TestTemplateErrorHandling(t *testing.T) {
	baseLayout := `{{define "layout"}}<!DOCTYPE html>
<html><head><title>{{template "title" .}}</title></head><body>{{template "content" .}}</body></html>{{end}}`

	// Create error template with complete definitions
	errorTmpl := template.Must(template.New("layout").Parse(baseLayout))
	template.Must(errorTmpl.New("title").Parse(`{{define "title"}}Error{{end}}`))
	template.Must(errorTmpl.New("content").Parse(`{{define "content"}}<h1>{{.Title}}</h1><p>{{.Message}}</p>{{end}}`))

	// Create verify template that will fail during execution
	verifyTmpl := template.Must(template.New("layout").Parse(baseLayout))
	template.Must(verifyTmpl.New("title").Parse(`{{define "title"}}Verify{{end}}`))
	template.Must(verifyTmpl.New("content").Parse(`{{define "content"}}
		{{/* Access a field that doesn't exist to trigger execution error */}}
		{{.NonExistentStruct.Field}}
	{{end}}`))

	// Create complete template as required by Templates struct
	completeTmpl := template.Must(template.New("layout").Parse(baseLayout))
	template.Must(completeTmpl.New("title").Parse(`{{define "title"}}Complete{{end}}`))
	template.Must(completeTmpl.New("content").Parse(`{{define "content"}}<h1>Complete</h1>{{end}}`))

	templates := &Templates{
		verify:   verifyTmpl,
		error:    errorTmpl,
		complete: completeTmpl,
	}

	mock := newMockResponseWriter()
	data := VerifyData{
		CSRFToken: "test-token",
	}

	err := templates.RenderVerify(mock, data)
	if err == nil {
		t.Fatal("RenderVerify() with error-producing template did not return error")
	}

	var templateErr *TemplateError
	if !errors.As(err, &templateErr) {
		t.Fatalf("error was not *TemplateError, got %T", err)
	}

	// Verify error details
	if !strings.Contains(templateErr.Message, "failed to render template") {
		t.Errorf("unexpected error message: %v", templateErr.Message)
	}

	// Verify cause mentions missing field
	cause := templateErr.Unwrap()
	if !strings.Contains(cause.Error(), "NonExistentStruct") {
		t.Errorf("error cause does not mention missing field: %v", cause)
	}

	// Verify error template rendered with expected content
	if !mock.Contains("Error", "Unable to display verification page") {
		t.Error("error template missing expected content")
	}
}
