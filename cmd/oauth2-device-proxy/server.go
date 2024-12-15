package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/oauth2"

	"github.com/jmdots/oauth2-device-proxy/internal/csrf"
	"github.com/jmdots/oauth2-device-proxy/internal/deviceflow"
	"github.com/jmdots/oauth2-device-proxy/internal/templates"
)

type server struct {
	cfg       Config
	router    *chi.Mux
	flow      *deviceflow.Flow
	templates *templates.Templates
	csrf      *csrf.Manager
	oauth     *oauth2.Config
}

func newServer(cfg Config, flow *deviceflow.Flow, csrfManager *csrf.Manager) (*server, error) {
	// Load templates
	tmpls, err := templates.LoadTemplates()
	if err != nil {
		return nil, fmt.Errorf("loading templates: %w", err)
	}

	// Configure OAuth client
	oauth := &oauth2.Config{
		ClientID:     cfg.OAuth.ClientID,
		ClientSecret: cfg.OAuth.ClientSecret,
		RedirectURL:  cfg.BaseURL + "/device/complete",
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.OAuth.AuthorizationEndpoint,
			TokenURL: cfg.OAuth.TokenEndpoint,
		},
	}

	srv := &server{
		cfg:       cfg,
		router:    chi.NewRouter(),
		flow:      flow,
		templates: tmpls,
		csrf:      csrfManager,
		oauth:     oauth,
	}

	// Set up middleware
	srv.router.Use(middleware.Logger)
	srv.router.Use(middleware.Recoverer)
	srv.router.Use(middleware.RealIP)
	srv.router.Use(middleware.Timeout(30 * time.Second))

	// Register routes
	srv.routes()

	return srv, nil
}

func (s *server) routes() {
	// Health check endpoint
	s.router.Get("/health", s.handleHealth())

	// Device flow endpoints per RFC 8628 section 3.3-3.4
	s.router.Route("/device", func(r chi.Router) {
		// Device authorization endpoints (RFC 8628 section 3.2)
		r.Post("/code", s.handleDeviceCode())   // Device code request
		r.Post("/token", s.handleDeviceToken()) // Token polling

		// User verification endpoints (RFC 8628 section 3.3)
		r.Route("/verify", func(v chi.Router) {
			v.Get("/", s.handleVerifyForm())    // Show verification form
			v.Post("/", s.handleVerifySubmit()) // Process verification
		})

		// OAuth callback handling
		r.Get("/complete", s.handleDeviceComplete())
	})
}

// ServeHTTP implements http.Handler
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// handleVerifyForm shows the verification form
func (s *server) handleVerifyForm() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate CSRF token
		token, err := s.csrf.GenerateToken(r.Context())
		if err != nil {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "System Error",
				Message: "Unable to process request. Please try again.",
			}); err != nil {
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}
			return
		}

		// Get prefilled code from query string
		code := r.URL.Query().Get("code")

		// Render verification form
		data := templates.VerifyData{
			PrefilledCode:   code,
			CSRFToken:       token,
			VerificationURI: s.cfg.BaseURL + "/device/verify",
		}

		if err := s.templates.RenderVerify(w, data); err != nil {
			http.Error(w, "error rendering page", http.StatusInternalServerError)
		}
	}
}

// handleVerifySubmit processes the verification form submission
func (s *server) handleVerifySubmit() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Verify CSRF token
		if err := s.csrf.ValidateToken(r.Context(), r.PostFormValue("csrf_token")); err != nil {
			if err := s.templates.RenderError(w, templates.ErrorData{
				Title:   "Invalid Request",
				Message: "Please try submitting the form again.",
			}); err != nil {
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}
			return
		}

		// Get and validate the user code
		code := r.PostFormValue("code")
		deviceCode, err := s.flow.VerifyUserCode(r.Context(), code)
		if err != nil {
			data := templates.VerifyData{
				Error:     "Invalid or expired code. Please try again.",
				CSRFToken: r.PostFormValue("csrf_token"),
			}
			if err := s.templates.RenderVerify(w, data); err != nil {
				http.Error(w, "error rendering page", http.StatusInternalServerError)
			}
			return
		}

		// Code is valid - redirect to OAuth provider
		params := map[string]string{
			"response_type": "code",
			"client_id":     deviceCode.ClientID,
			"redirect_uri":  s.cfg.BaseURL + "/device/complete",
			"state":         deviceCode.DeviceCode,
		}
		if deviceCode.Scope != "" {
			params["scope"] = deviceCode.Scope
		}

		http.Redirect(w, r, s.buildOAuthURL(params), http.StatusFound)
	}
}

// Helper methods

func (s *server) checkHealth(ctx context.Context) error {
	// Check all components
	if err := s.flow.CheckHealth(ctx); err != nil {
		return err
	}
	if err := s.csrf.CheckHealth(ctx); err != nil {
		return err
	}
	return nil
}

func (s *server) buildOAuthURL(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	return s.cfg.OAuth.AuthorizationEndpoint + "?" + values.Encode()
}

func (s *server) exchangeCode(ctx context.Context, code string, deviceCode *deviceflow.DeviceCode) (*deviceflow.TokenResponse, error) {
	token, err := s.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}

	return &deviceflow.TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()), // Using time.Until for accuracy
		RefreshToken: token.RefreshToken,
		Scope:        deviceCode.Scope, // Preserve original scope
	}, nil
}
