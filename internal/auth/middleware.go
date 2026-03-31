package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// auditClientIDHeader is the internal header name used to propagate client_id
// to the audit middleware. This must match audit.AuditClientIDHeader.
const auditClientIDHeader = "X-Audit-Client-Id"

// Middleware provides HTTP middleware for OAuth2 token verification.
type Middleware struct {
	introspector Introspector
	cache        *TokenCache
	logger       *slog.Logger
	skipPaths    map[string]bool
}

// MiddlewareOption configures the auth Middleware.
type MiddlewareOption func(*Middleware)

// WithMiddlewareLogger sets a custom logger for the middleware.
func WithMiddlewareLogger(logger *slog.Logger) MiddlewareOption {
	return func(m *Middleware) {
		m.logger = logger
	}
}

// WithSkipPaths sets paths that bypass token verification (e.g., "/health").
func WithSkipPaths(paths ...string) MiddlewareOption {
	return func(m *Middleware) {
		for _, p := range paths {
			m.skipPaths[p] = true
		}
	}
}

// WithCache sets a custom token cache for the middleware.
func WithCache(cache *TokenCache) MiddlewareOption {
	return func(m *Middleware) {
		m.cache = cache
	}
}

// NewMiddleware creates a new auth middleware with the given introspector.
func NewMiddleware(introspector Introspector, opts ...MiddlewareOption) *Middleware {
	m := &Middleware{
		introspector: introspector,
		cache:        NewTokenCache(),
		logger:       slog.Default(),
		skipPaths:    make(map[string]bool),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Handler wraps the given handler with token verification.
// Requests to skip paths (e.g., /health) are passed through without verification.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for configured paths.
		if m.skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Extract Bearer token from Authorization header.
		token, err := extractBearerToken(r)
		if err != nil {
			m.logger.Warn("token extraction failed",
				"error", err.Error(),
				"remote_addr", r.RemoteAddr,
			)
			writeUnauthorized(w, err.Error())
			return
		}

		// Check cache first.
		if result, ok := m.cache.Get(token); ok {
			if result.Active {
				info := &TokenInfo{
					ClientID: result.ClientID,
					Scopes:   parseScopes(result.Scope),
				}
				ctx := WithTokenInfo(r.Context(), info)
				m.logger.Debug("token validated from cache",
					"client_id", result.ClientID,
				)
				w.Header().Set(auditClientIDHeader, result.ClientID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// Cached as inactive.
			m.logger.Warn("token is inactive (cached)",
				"remote_addr", r.RemoteAddr,
			)
			writeUnauthorized(w, "token is not active")
			return
		}

		// Introspect the token with Hydra.
		result, err := m.introspector.Introspect(r.Context(), token)
		if err != nil {
			m.logger.Error("token introspection failed",
				"error", err.Error(),
				"remote_addr", r.RemoteAddr,
			)
			writeUnauthorized(w, "token verification failed")
			return
		}

		// Cache the result regardless of active/inactive.
		m.cache.Set(token, result)

		if !result.Active {
			m.logger.Warn("token is not active",
				"remote_addr", r.RemoteAddr,
			)
			writeUnauthorized(w, "token is not active")
			return
		}

		// Token is valid; store info in context.
		info := &TokenInfo{
			ClientID: result.ClientID,
			Scopes:   parseScopes(result.Scope),
		}
		ctx := WithTokenInfo(r.Context(), info)
		m.logger.Info("request authenticated",
			"client_id", result.ClientID,
			"remote_addr", r.RemoteAddr,
		)
		// Set internal header for audit middleware to capture client_id
		// across middleware boundaries (audit wraps auth externally).
		w.Header().Set(auditClientIDHeader, result.ClientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeUnauthorized writes a 401 response with the WWW-Authenticate header
// per RFC 7235 Section 4.1.
func writeUnauthorized(w http.ResponseWriter, description string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+description+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	resp := struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{
		Error:   "unauthorized",
		Message: description,
	}
	//nolint:errcheck // best-effort write to response
	json.NewEncoder(w).Encode(resp)
}

// parseScopes splits a space-separated scope string into a slice.
func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}
