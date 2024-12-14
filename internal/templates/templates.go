package templates

import (
	"bytes"
	"embed"
	"html/template"
	"io"
)

//go:embed html/*.html
var content embed.FS

// Templates manages the HTML templates
type Templates struct {
	verify   *template.Template
	complete *template.Template
	error    *template.Template
}

// LoadTemplates loads and parses all HTML templates
func LoadTemplates() (*Templates, error) {
	t := &Templates{}
	var err error

	// Load verification page template
	if t.verify, err = template.ParseFS(content, "html/verify.html", "html/layout.html"); err != nil {
		return nil, err
	}

	// Load complete page template
	if t.complete, err = template.ParseFS(content, "html/complete.html", "html/layout.html"); err != nil {
		return nil, err
	}

	// Load error page template
	if t.error, err = template.ParseFS(content, "html/error.html", "html/layout.html"); err != nil {
		return nil, err
	}

	return t, nil
}

// VerifyData holds data for the code verification page
type VerifyData struct {
	PrefilledCode string
	CSRFToken     string
	Error         string
}

// RenderVerify renders the code verification page
func (t *Templates) RenderVerify(w io.Writer, data VerifyData) error {
	return t.verify.ExecuteTemplate(w, "layout", data)
}

// CompleteData holds data for the completion page
type CompleteData struct {
	Message string
}

// RenderComplete renders the completion page
func (t *Templates) RenderComplete(w io.Writer, data CompleteData) error {
	return t.complete.ExecuteTemplate(w, "layout", data)
}

// ErrorData holds data for the error page
type ErrorData struct {
	Title   string
	Message string
}

// RenderError renders the error page
func (t *Templates) RenderError(w io.Writer, data ErrorData) error {
	return t.error.ExecuteTemplate(w, "layout", data)
}

// RenderToString renders a template to a string
func (t *Templates) RenderToString(tmpl *template.Template, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
