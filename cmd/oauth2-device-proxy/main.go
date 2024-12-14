package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kelseyhightower/envconfig"
	"github.com/redis/go-redis/v9"

	"github.com/jmdots/oauth2-device-proxy/internal/deviceflow"
)

// Version is set by the build process
var Version = "dev"

// Config holds server configuration loaded from environment variables
type Config struct {
	Port              int           `envconfig:"PORT" default:"8080"`
	RedisURL          string        `envconfig:"REDIS_URL" required:"true"`
	KeycloakURL       string        `envconfig:"KEYCLOAK_URL" required:"true"`
	KeycloakRealm     string        `envconfig:"KEYCLOAK_REALM" required:"true"`
	KeycloakClientID  string        `envconfig:"KEYCLOAK_CLIENT_ID" required:"true"`
	CodeExpiry        time.Duration `envconfig:"CODE_EXPIRY" default:"15m"`
	PollInterval      time.Duration `envconfig:"POLL_INTERVAL" default:"5s"`
	MaxPollsPerMinute int           `envconfig:"MAX_POLLS_PER_MINUTE" default:"12"`
	BaseURL           string        `envconfig:"BASE_URL" required:"true"`
}

type server struct {
	cfg    Config
	router *chi.Mux
	flow   *deviceflow.Flow
}

func main() {
	// Load configuration from environment
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Create Redis client
	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Error parsing Redis URL: %v", err)
	}
	redisClient := redis.NewClient(redisOpts)

	// Verify Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Error connecting to Redis: %v", err)
	}

	// Initialize device flow
	store := deviceflow.NewRedisStore(redisClient)
	flow := deviceflow.NewFlow(store, cfg.BaseURL,
		deviceflow.WithExpiryDuration(cfg.CodeExpiry),
		deviceflow.WithPollInterval(cfg.PollInterval),
		deviceflow.WithRateLimit(time.Minute, cfg.MaxPollsPerMinute),
	)

	// Create and configure server
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

	// Create HTTP server
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: srv.router,
	}

	// Channel to listen for errors coming from the server
	serverErrors := make(chan error, 1)

	// Start server
	go func() {
		log.Printf("Server listening on port %d", cfg.Port)
		serverErrors <- httpServer.ListenAndServe()
	}()

	// Channel to listen for interrupt signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a signal or error
	select {
	case err := <-serverErrors:
		log.Fatalf("Error starting server: %v", err)

	case <-shutdown:
		log.Println("Starting shutdown")

		// Create context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Shutdown server
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down server: %v", err)
			if err := httpServer.Close(); err != nil {
				log.Printf("Error closing server: %v", err)
			}
		}

		// Close Redis connection
		if err := redisClient.Close(); err != nil {
			log.Printf("Error closing Redis connection: %v", err)
		}
	}
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

// Health check handler
func (s *server) handleHealth() http.HandlerFunc {
	type healthResponse struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := healthResponse{
			Status:  "ok",
			Version: Version,
		}

		// Check Redis connection
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()

		rdb := s.flow.Store().(*deviceflow.RedisStore).Client()
		err := rdb.Ping(ctx).Err()
		if err != nil {
			resp.Status = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		writeJSON(w, resp)
	}
}

// Device code request handler
func (s *server) handleDeviceCode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		clientID := r.Form.Get("client_id")
		if clientID == "" {
			http.Error(w, "missing client_id", http.StatusBadRequest)
			return
		}

		scope := r.Form.Get("scope")

		code, err := s.flow.RequestDeviceCode(r.Context(), clientID, scope)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, code)
	}
}

// Device token polling handler
func (s *server) handleDeviceToken() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			writeError(w, "unsupported_grant_type")
			return
		}

		deviceCode := r.Form.Get("device_code")
		if deviceCode == "" {
			writeError(w, "invalid_request")
			return
		}

		token, err := s.flow.CheckDeviceCode(r.Context(), deviceCode)
		if err != nil {
			switch {
			case errors.Is(err, deviceflow.ErrInvalidDeviceCode):
				writeError(w, "invalid_grant")
			case errors.Is(err, deviceflow.ErrExpiredCode):
				writeError(w, "expired_token")
			case errors.Is(err, deviceflow.ErrPendingAuthorization):
				writeError(w, "authorization_pending")
			case errors.Is(err, deviceflow.ErrSlowDown):
				writeError(w, "slow_down")
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		writeJSON(w, token)
	}
}

// Device verification page handler
func (s *server) handleDeviceVerification() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement HTML page for code entry
		http.Error(w, "not implemented", http.StatusNotImplemented)
	}
}

// Device complete page handler
func (s *server) handleDeviceComplete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Implement success page
		http.Error(w, "not implemented", http.StatusNotImplemented)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "error encoding response", http.StatusInternalServerError)
		return
	}
}

func writeError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}
