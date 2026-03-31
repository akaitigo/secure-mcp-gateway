// Package auth provides OAuth2 token verification middleware using ORY Hydra.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxTokenLength is the maximum allowed Bearer token length.
const maxTokenLength = 2048

// IntrospectionResult holds the result of a token introspection call.
type IntrospectionResult struct {
	// ClientID is the OAuth2 client identifier.
	ClientID string `json:"client_id,omitempty"`
	// Scope contains space-separated scope values.
	Scope string `json:"scope,omitempty"`
	// ExpiresAt is the token expiration time (Unix timestamp).
	ExpiresAt int64 `json:"exp,omitempty"`
	// Active indicates whether the token is currently active.
	Active bool `json:"active"`
}

// TokenInfo holds the extracted and validated token information,
// passed through the request context to downstream handlers.
type TokenInfo struct {
	// ClientID is the authenticated OAuth2 client identifier.
	ClientID string
	// Scopes is the list of granted scopes.
	Scopes []string
}

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

// tokenInfoKey is the context key for TokenInfo.
const tokenInfoKey contextKey = "tokenInfo"

// WithTokenInfo stores TokenInfo in the request context.
func WithTokenInfo(ctx context.Context, info *TokenInfo) context.Context {
	return context.WithValue(ctx, tokenInfoKey, info)
}

// GetTokenInfo retrieves TokenInfo from the request context.
// Returns nil if no token info is present.
func GetTokenInfo(ctx context.Context) *TokenInfo {
	info, ok := ctx.Value(tokenInfoKey).(*TokenInfo)
	if !ok {
		return nil
	}
	return info
}

// Introspector defines the interface for token introspection.
// This allows mocking in tests.
type Introspector interface {
	Introspect(ctx context.Context, token string) (*IntrospectionResult, error)
}

// HydraIntrospector performs token introspection against ORY Hydra.
type HydraIntrospector struct {
	httpClient *http.Client
	adminURL   string
}

// NewHydraIntrospector creates a new HydraIntrospector.
func NewHydraIntrospector(adminURL string, httpClient *http.Client) (*HydraIntrospector, error) {
	if adminURL == "" {
		return nil, errors.New("hydra admin URL is required")
	}

	if _, err := url.ParseRequestURI(adminURL); err != nil {
		return nil, fmt.Errorf("invalid hydra admin URL: %w", err)
	}

	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	return &HydraIntrospector{
		adminURL:   strings.TrimRight(adminURL, "/"),
		httpClient: httpClient,
	}, nil
}

// Introspect calls the ORY Hydra token introspection endpoint.
// See RFC 7662 for the token introspection protocol.
func (h *HydraIntrospector) Introspect(ctx context.Context, token string) (*IntrospectionResult, error) {
	endpoint := h.adminURL + "/admin/oauth2/introspect"

	form := url.Values{"token": {token}}
	// endpoint is derived from the trusted HYDRA_ADMIN_URL server configuration, not user input.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode())) //nolint:gosec // trusted config
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req) //nolint:gosec // trusted config (see above)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection endpoint returned status %d", resp.StatusCode)
	}

	var result IntrospectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	return &result, nil
}

// extractBearerToken extracts the Bearer token from the Authorization header.
// Returns an error if the header is missing, malformed, or the token exceeds maxTokenLength.
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("authorization header must use Bearer scheme")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", errors.New("empty Bearer token")
	}

	if len(token) > maxTokenLength {
		return "", fmt.Errorf("token exceeds maximum length of %d characters", maxTokenLength)
	}

	// Validate token contains only ASCII printable characters (0x20-0x7E).
	for _, c := range token {
		if c < 0x20 || c > 0x7E {
			return "", errors.New("token contains invalid characters")
		}
	}

	return token, nil
}
