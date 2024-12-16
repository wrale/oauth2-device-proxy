package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/oauth2"

	"github.com/wrale/oauth2-device-proxy/cmd/oauth2-device-proxy/handlers/device"
	"github.com/wrale/oauth2-device-proxy/cmd/oauth2-device-proxy/handlers/health"
	"github.com/wrale/oauth2-device-proxy/cmd/oauth2-device-proxy/handlers/token"
	"github.com/wrale/oauth2-device-proxy/cmd/oauth2-device-proxy/handlers/verify"
	"github.com/wrale/oauth2-device-proxy/internal/csrf"
	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
	"github.com/wrale/oauth2-device-proxy/internal/templates"
)

type server struct {
	cfg Config
	mux *chi.Mux
}

// newServer creates a new HTTP server that implements RFC 8628 device authorization flows
func newServer(cfg Config, flow deviceflow.Flow, csrfManager *csrf.Manager) (*server, error) {
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

	// Initialize handlers per RFC 8628 requirements:
	// - /health for server status
	// - /device/code for authorization requests (§3.1-3.2)
	// - /device/token for token requests (§3.4-3.5)
	// - /device for user interaction (§3.3)
	healthHandler := health.New(flow)
	deviceHandler := device.New(flow)
	tokenHandler := token.New(token.Config{Flow: flow})
	verifyHandler := verify.New(verify.Config{
		Flow:      flow,
		Templates: tmpls,
		CSRF:      csrfManager,
		OAuth:     oauth,
		BaseURL:   cfg.BaseURL,
	})

	srv := &server{
		cfg: cfg,
		mux: chi.NewRouter(),
	}

	// Set up middleware stack
	srv.mux.Use(middleware.Logger)
	srv.mux.Use(middleware.Recoverer)
	srv.mux.Use(middleware.RealIP)
	srv.mux.Use(middleware.Timeout(30 * time.Second))

	// Register routes
	srv.mux.Handle("/health", healthHandler)

	// Device authorization endpoints (RFC 8628)
	srv.mux.Handle("/device/code", deviceHandler) // §3.1-3.2
	srv.mux.Handle("/device/token", tokenHandler) // §3.4-3.5

	// User verification endpoints - §3.3
	srv.mux.Get("/device", verifyHandler.HandleForm)
	srv.mux.Post("/device", verifyHandler.HandleSubmit)
	srv.mux.Get("/device/complete", verifyHandler.HandleComplete)

	return srv, nil
}

// ServeHTTP implements http.Handler
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
