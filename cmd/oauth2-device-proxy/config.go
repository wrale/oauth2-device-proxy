package main

import "time"

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

	// CSRF Configuration
	CSRFSecret      string        `envconfig:"CSRF_SECRET" required:"true"`
	CSRFTokenExpiry time.Duration `envconfig:"CSRF_TOKEN_EXPIRY" default:"1h"`

	// HTTP Server Timeouts
	ReadHeaderTimeout time.Duration `envconfig:"READ_HEADER_TIMEOUT" default:"10s"`
	ReadTimeout       time.Duration `envconfig:"READ_TIMEOUT" default:"30s"`
	WriteTimeout      time.Duration `envconfig:"WRITE_TIMEOUT" default:"30s"`
	IdleTimeout       time.Duration `envconfig:"IDLE_TIMEOUT" default:"120s"`

	// OAuth Configuration
	OAuth struct {
		ClientID              string `envconfig:"OAUTH_CLIENT_ID" required:"true"`
		ClientSecret          string `envconfig:"OAUTH_CLIENT_SECRET" required:"true"`
		AuthorizationEndpoint string `envconfig:"OAUTH_AUTH_ENDPOINT" required:"true"`
		TokenEndpoint         string `envconfig:"OAUTH_TOKEN_ENDPOINT" required:"true"`
	}
}
