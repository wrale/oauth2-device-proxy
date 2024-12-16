// Package verify provides verification flow handlers per RFC 8628 section 3.3
package verify

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

// exchangeCode exchanges an authorization code for tokens per RFC 8628 section 3.5
func (h *Handler) exchangeCode(ctx context.Context, code string, deviceCode *deviceflow.DeviceCode) (*deviceflow.TokenResponse, error) {
	// Exchange code using OAuth2 config
	token, err := h.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code: %w", err)
	}

	// Convert oauth2.Token to deviceflow.TokenResponse per RFC 8628
	return &deviceflow.TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		RefreshToken: token.RefreshToken,
		Scope:        deviceCode.Scope,
	}, nil
}
