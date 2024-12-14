package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Keycloak endpoint paths
	tokenPath       = "/protocol/openid-connect/token"
	tokenInfoPath   = "/protocol/openid-connect/token/introspect"
	revocationPath  = "/protocol/openid-connect/revoke"
	healthCheckPath = "/.well-known/openid-configuration"

	// HTTP request timeouts
	defaultTimeout = 10 * time.Second
)

// KeycloakProvider implements the Provider interface for Keycloak
type KeycloakProvider struct {
	client        *http.Client
	clientID      string
	clientSecret  string
	tokenURL      string
	tokenInfoURL  string
	revocationURL string
	healthURL     string
}

// KeycloakConfig extends Config with Keycloak-specific settings
type KeycloakConfig struct {
	Config
	Realm string
}

// NewKeycloakProvider creates a new Keycloak provider
func NewKeycloakProvider(cfg KeycloakConfig) (*KeycloakProvider, error) {
	// Validate required fields
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if cfg.Realm == "" {
		return nil, fmt.Errorf("realm is required")
	}

	// Clean and validate base URL
	baseURL := strings.TrimSuffix(cfg.BaseURL, "/")
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Build realm URL
	realmURL := fmt.Sprintf("%s/realms/%s", baseURL, cfg.Realm)

	// Create provider with configured client
	return &KeycloakProvider{
		client:        &http.Client{Timeout: defaultTimeout},
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		tokenURL:      realmURL + tokenPath,
		tokenInfoURL:  realmURL + tokenInfoPath,
		revocationURL: realmURL + revocationPath,
		healthURL:     realmURL + healthCheckPath,
	}, nil
}

// ExchangeCode exchanges an authorization code for tokens
func (p *KeycloakProvider) ExchangeCode(ctx context.Context, code, redirectURI string) (*Token, error) {
	// Prepare token request
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request and handle response
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending token request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	// Check for error responses
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &errResp); err != nil {
			return nil, fmt.Errorf("invalid error response: %w", err)
		}
		switch errResp.Error {
		case "invalid_grant":
			return nil, ErrInvalidGrant
		default:
			return nil, fmt.Errorf("token request failed: %s: %s", errResp.Error, errResp.ErrorDescription)
		}
	}

	// Parse successful response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	// Create token with calculated expiry
	token := &Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return token, nil
}

// ValidateToken validates an access token and returns its info
func (p *KeycloakProvider) ValidateToken(ctx context.Context, token string) (*TokenInfo, error) {
	// Prepare introspection request
	data := url.Values{
		"token":         {token},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenInfoURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token info request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request and handle response
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending token info request: %w", err)
	}
	defer resp.Body.Close()

	// Read and parse response
	var info TokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("parsing token info response: %w", err)
	}

	// Check token state
	if !info.Active {
		return nil, ErrInvalidToken
	}
	if time.Now().After(info.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	return &info, nil
}

// RefreshToken refreshes an access token using a refresh token
func (p *KeycloakProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	// Prepare refresh request
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request and handle response
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending refresh request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading refresh response: %w", err)
	}

	// Check for error responses
	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &errResp); err != nil {
			return nil, fmt.Errorf("invalid error response: %w", err)
		}
		switch errResp.Error {
		case "invalid_grant":
			return nil, ErrInvalidGrant
		default:
			return nil, fmt.Errorf("refresh request failed: %s: %s", errResp.Error, errResp.ErrorDescription)
		}
	}

	// Parse successful response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing refresh response: %w", err)
	}

	// Create token with calculated expiry
	token := &Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return token, nil
}

// RevokeToken revokes an access or refresh token
func (p *KeycloakProvider) RevokeToken(ctx context.Context, token string) error {
	// Prepare revocation request
	data := url.Values{
		"token":         {token},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, "POST", p.revocationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("creating revocation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request and check response
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending revocation request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revocation request failed: %s: %s", resp.Status, body)
	}

	return nil
}

// CheckHealth verifies the provider is accessible
func (p *KeycloakProvider) CheckHealth(ctx context.Context) error {
	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", p.healthURL, nil)
	if err != nil {
		return fmt.Errorf("creating health check request: %w", err)
	}

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending health check request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return ErrProviderUnavailable
	}

	return nil
}
