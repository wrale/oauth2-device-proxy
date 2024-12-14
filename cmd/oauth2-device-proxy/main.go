package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/redis/go-redis/v9"

	"github.com/jmdots/oauth2-device-proxy/internal/csrf"
	"github.com/jmdots/oauth2-device-proxy/internal/deviceflow"
)

// Version is set by the build process
var Version = "dev"

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

	// Initialize CSRF protection
	csrfStore := csrf.NewRedisStore(redisClient)
	csrfManager := csrf.NewManager(csrfStore, []byte(cfg.CSRFSecret), cfg.CSRFTokenExpiry)

	// Create and configure server
	srv, err := newServer(cfg, flow, csrfManager)
	if err != nil {
		log.Fatalf("Error creating server: %v", err)
	}

	// Create HTTP server with proper timeout configurations
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           srv.router,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
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
