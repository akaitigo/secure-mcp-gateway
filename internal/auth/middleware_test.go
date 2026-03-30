package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIntrospector implements Introspector for testing.
type mockIntrospector struct {
	result *IntrospectionResult
	err    error
	calls  int
}

func (m *mockIntrospector) Introspect(_ context.Context, _ string) (*IntrospectionResult, error) {
	m.calls++
	return m.result, m.err
}

// echoHandler is a simple handler that writes token info from context.
func echoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := GetTokenInfo(r.Context())
		if info != nil {
			w.Header().Set("X-Client-ID", info.ClientID)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func TestMiddleware_ValidToken(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{
		result: &IntrospectionResult{
			Active:   true,
			ClientID: "test-client",
			Scope:    "tools:read tools:call",
		},
	}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	handler := mw.Handler(echoHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "test-client", rec.Header().Get("X-Client-ID"))
	assert.Equal(t, 1, mock.calls)
}

func TestMiddleware_InvalidToken(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{
		result: &IntrospectionResult{
			Active: false,
		},
	}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	handler := mw.Handler(echoHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "invalid_token")
}

func TestMiddleware_MissingToken(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	handler := mw.Handler(echoHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "Bearer")
	assert.Equal(t, 0, mock.calls, "introspector should not be called when no token is present")
}

func TestMiddleware_IntrospectionError(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{
		err: errors.New("hydra is down"),
	}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	handler := mw.Handler(echoHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "token verification failed")
}

func TestMiddleware_SkipPath(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
		WithSkipPaths("/health"),
	)

	handler := mw.Handler(echoHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	// No Authorization header.

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())
	assert.Equal(t, 0, mock.calls, "introspector should not be called for skip paths")
}

func TestMiddleware_CacheHit(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{
		result: &IntrospectionResult{
			Active:   true,
			ClientID: "cached-client",
			Scope:    "tools:read",
		},
	}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	handler := mw.Handler(echoHandler())

	// First request: cache miss, calls introspector.
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "Bearer cached-token")
	handler.ServeHTTP(rec1, req1)

	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, 1, mock.calls)

	// Second request: cache hit, should NOT call introspector again.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer cached-token")
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, "cached-client", rec2.Header().Get("X-Client-ID"))
	assert.Equal(t, 1, mock.calls, "introspector should not be called for cached tokens")
}

func TestMiddleware_CachedInactiveToken(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{
		result: &IntrospectionResult{
			Active: false,
		},
	}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	handler := mw.Handler(echoHandler())

	// First request: cache miss, calls introspector.
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "Bearer inactive-token")
	handler.ServeHTTP(rec1, req1)

	assert.Equal(t, http.StatusUnauthorized, rec1.Code)
	assert.Equal(t, 1, mock.calls)

	// Second request: cache hit for inactive token.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer inactive-token")
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusUnauthorized, rec2.Code)
	assert.Equal(t, 1, mock.calls, "introspector should not be called for cached inactive tokens")
}

func TestMiddleware_MultipleSkipPaths(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
		WithSkipPaths("/health", "/ready", "/metrics"),
	)

	handler := mw.Handler(echoHandler())

	paths := []string{"/health", "/ready", "/metrics"}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "path %s should be skipped", path)
	}

	assert.Equal(t, 0, mock.calls)
}

func TestMiddleware_NonBearerScheme(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	handler := mw.Handler(echoHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 0, mock.calls)
}

func TestMiddleware_TokenInfoPropagated(t *testing.T) {
	t.Parallel()

	mock := &mockIntrospector{
		result: &IntrospectionResult{
			Active:   true,
			ClientID: "propagated-client",
			Scope:    "tools:read tools:call admin",
		},
	}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
	)

	var capturedInfo *TokenInfo
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedInfo = GetTokenInfo(r.Context())
	})

	handler := mw.Handler(inner)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer prop-token")

	handler.ServeHTTP(rec, req)

	require.NotNil(t, capturedInfo)
	assert.Equal(t, "propagated-client", capturedInfo.ClientID)
	assert.Equal(t, []string{"tools:read", "tools:call", "admin"}, capturedInfo.Scopes)
}

func TestMiddleware_WithCustomCache(t *testing.T) {
	t.Parallel()

	cache := NewTokenCache()
	cache.Set("pre-cached-token", &IntrospectionResult{
		Active:   true,
		ClientID: "pre-cached-client",
		Scope:    "tools:read",
	})

	mock := &mockIntrospector{}

	mw := NewMiddleware(mock,
		WithMiddlewareLogger(newTestLogger()),
		WithCache(cache),
	)

	handler := mw.Handler(echoHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer pre-cached-token")

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "pre-cached-client", rec.Header().Get("X-Client-ID"))
	assert.Equal(t, 0, mock.calls, "should use pre-populated cache")
}

func TestWriteUnauthorized_ResponseFormat(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	writeUnauthorized(rec, "test error message")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, "invalid_token")
	assert.Contains(t, wwwAuth, "test error message")

	assert.Contains(t, rec.Body.String(), "unauthorized")
	assert.Contains(t, rec.Body.String(), "test error message")
}
