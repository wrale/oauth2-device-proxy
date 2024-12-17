package templates

import (
	"errors"
	"testing"
)

func TestLoadTemplates(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "successfully loads all templates",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			templates, err := LoadTemplates()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadTemplates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && templates == nil {
				t.Error("LoadTemplates() returned nil templates")
			}
		})
	}
}

func TestTemplateError(t *testing.T) {
	cause := errors.New("original error")
	err := &TemplateError{
		Cause:   cause,
		Message: "template failed",
	}

	// Test Error() string format
	want := "template error: template failed: original error"
	if got := err.Error(); got != want {
		t.Errorf("TemplateError.Error() = %q, want %q", got, want)
	}

	// Test error unwrapping
	if unwrapped := errors.Unwrap(err); unwrapped != cause {
		t.Errorf("errors.Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestTemplatesInitialization(t *testing.T) {
	templates := setupTemplates(t)

	// Verify that all required templates are loaded
	if templates.verify == nil {
		t.Error("verify template not loaded")
	}
	if templates.complete == nil {
		t.Error("complete template not loaded")
	}
	if templates.error == nil {
		t.Error("error template not loaded")
	}
}
