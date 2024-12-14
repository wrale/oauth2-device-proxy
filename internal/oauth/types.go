// Package oauth provides OAuth2 provider integration with support for device flow
package oauth

import (
	"context"
	"errors"
	"time"
)

// Common errors returned by providers
var (
	ErrInvalidGrant        = errors.New("invalid grant")
	ErrInvalidToken        = errors.New("invalid token")
	ErrTokenExpired        = errors.New("token expired")
	ErrProviderUnavailable = errors.New("oauth provider unavailable")
)

// Token represents an OAuth2 access token with refresh capabilities
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// TokenInfo contains additional information about a validated token
type TokenInfo struct {
	Active    bool      `json:"active"`
	Subject   string    `json:"sub"`
	ClientID  string    `json:"client_id"`
	Username  string    `json:"username,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	Issuer    string    `json:"iss"`
}

// Provider defines the interface for OAuth2 providers supporting device flow
type Provider interface {
	// ExchangeCode exchanges an authorization code for tokens
	ExchangeCode(ctx context.Context, code, redirectURI string) (*Token, error)

	// ValidateToken validates an access token and returns its info
	ValidateToken(ctx context.Context, token string) (*TokenInfo, error)

	// RefreshToken refreshes an access token using a refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*Token, error)

	// RevokeToken revokes an access or refresh token
	RevokeToken(ctx context.Context, token string) error

	// CheckHealth verifies the provider is accessible
	CheckHealth(ctx context.Context) error
}

// Config holds common OAuth provider configuration
type Config struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
	RedirectURI  string
}
