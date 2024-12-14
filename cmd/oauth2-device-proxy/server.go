package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"time"

	"github.com/jmdots/oauth2-device-proxy/internal/deviceflow"
)

type server struct {
	cfg    Config
	router *chi.Mux
	flow   *deviceflow.Flow
}

func newServer(cfg Config, flow *deviceflow.Flow) *server {
	srv := &server{
		cfg:    cfg,
		router: chi.NewRouter(),
		flow:   flow,
	}

	// Set up middleware
	srv.router.Use(middleware.Logger)
	srv.router.Use(middleware.Recoverer)
	srv.router.Use(middleware.RealIP)
	srv.router.Use(middleware.Timeout(30 * time.Second))

	// Register routes
	srv.routes()

	return srv
}

func (s *server) routes() {
	// Health check endpoint
	s.router.Get("/health", s.handleHealth())

	// Device flow endpoints
	s.router.Post("/device/code", s.handleDeviceCode())
	s.router.Post("/device/token", s.handleDeviceToken())
	s.router.Get("/device", s.handleDeviceVerification())
	s.router.Get("/device/complete", s.handleDeviceComplete())
}
