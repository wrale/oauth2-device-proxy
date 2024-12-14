package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

	// Device flow endpoints
	s.router.Post("/device/code", s.handleDeviceCode())
	s.router.Post("/device/token", s.handleDeviceToken())
	s.router.Get("/device", s.handleDeviceVerification())
	s.router.Post("/device/verify", s.handleDeviceVerification())
	s.router.Get("/device/complete", s.handleDeviceComplete())
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
		ExpiresIn:    int(token.Expiry.Sub(time.Now()).Seconds()),
		RefreshToken: token.RefreshToken,
		Scope:        deviceCode.Scope, // Use the scope from the original device code request
	}, nil
}
