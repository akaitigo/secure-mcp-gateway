package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akaitigo/secure-mcp-gateway/internal/auth"
)

func newTestMiddleware(t *testing.T) (*Middleware, *bytes.Buffer, *Store) {
	t.Helper()
	var buf bytes.Buffer
	store := NewStore()
	logger := NewLoggerWithWriter(&buf, store)
	mw := NewMiddleware(logger, WithSkipPaths("/health"))
	return mw, &buf, store
}

func TestAuditMiddleware_LogsToolCall(t *testing.T) {
	t.Parallel()

	mw, buf, store := newTestMiddleware(t)

	// Simulate authenticated request with token info in context.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db-query"}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Set token info in context (simulating auth middleware).
	ctx := auth.WithTokenInfo(req.Context(), &auth.TokenInfo{
		ClientID: "test-client",
		Scopes:   []string{"tools:call"},
	})
	ctx = WithRequestID(ctx, "test-request-id")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify audit log.
	assert.Equal(t, 1, store.Count())
	entries, _ := store.List(0, 1)
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "test-client", entry.ClientID)
	assert.Equal(t, "tools/call", entry.ToolName)
	assert.Equal(t, DecisionAllow, entry.Decision)
	assert.Equal(t, "test-request-id", entry.RequestID)
	assert.Equal(t, "POST", entry.Metadata["http_method"])

	// Verify structured log output.
	var logOutput map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logOutput)
	require.NoError(t, err)
	assert.Equal(t, "test-client", logOutput["client_id"])
}

func TestAuditMiddleware_DenyOnUnauthorized(t *testing.T) {
	t.Parallel()

	mw, _, store := newTestMiddleware(t)

	// Inner handler returns 401 (simulating auth failure).
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	handler := mw.Handler(inner)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := WithRequestID(req.Context(), "deny-req-id")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	entries, _ := store.List(0, 1)
	require.Len(t, entries, 1)
	assert.Equal(t, DecisionDeny, entries[0].Decision)
	assert.Equal(t, unknownValue, entries[0].ClientID)
}

func TestAuditMiddleware_SkipHealthPath(t *testing.T) {
	t.Parallel()

	mw, _, store := newTestMiddleware(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, 0, store.Count())
}

func TestAuditMiddleware_LogsGetRequests(t *testing.T) {
	t.Parallel()

	mw, _, store := newTestMiddleware(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	ctx := WithRequestID(req.Context(), "sse-request-id")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, 1, store.Count())
	entries, _ := store.List(0, 1)
	require.Len(t, entries, 1)
	assert.Equal(t, "GET /sse", entries[0].ToolName)
	assert.Equal(t, DecisionAllow, entries[0].Decision)
}

func TestAuditMiddleware_NonJSONContentType(t *testing.T) {
	t.Parallel()

	mw, _, store := newTestMiddleware(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should still log with unknownValue tool name.
	assert.Equal(t, 1, store.Count())
	entries, _ := store.List(0, 1)
	assert.Equal(t, unknownValue, entries[0].ToolName)
}

func TestAuditMiddleware_NoTokenSensitiveData(t *testing.T) {
	t.Parallel()

	mw, buf, _ := newTestMiddleware(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	output := buf.String()
	assert.NotContains(t, output, "super-secret-token")
	assert.NotContains(t, output, "Bearer")
}

func TestAuditMiddleware_ForbiddenDecision(t *testing.T) {
	t.Parallel()

	mw, _, store := newTestMiddleware(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	handler := mw.Handler(inner)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	entries, _ := store.List(0, 1)
	require.Len(t, entries, 1)
	assert.Equal(t, DecisionDeny, entries[0].Decision)
}

func TestAuditMiddleware_BodyPreservedForDownstream(t *testing.T) {
	t.Parallel()

	mw, _, _ := newTestMiddleware(t)

	var receivedMethod string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Downstream should still be able to read the body.
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r.Body); err != nil {
			t.Error("failed to read body:", err)
		}
		var req map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &req); err == nil {
			receivedMethod, _ = req["method"].(string)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "tools/list", receivedMethod)
}

func TestAuditMiddleware_OversizedBodyRejected(t *testing.T) {
	t.Parallel()

	mw, _, store := newTestMiddleware(t)

	var downstreamBodySize int
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		downstreamBodySize = len(body)
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	// 1MB + 1 byte exceeds the maxRequestSize limit.
	oversizedBody := strings.Repeat("x", 1<<20+1)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// The MaxBytesReader should prevent the full body from being read.
	assert.LessOrEqual(t, downstreamBodySize, 1<<20,
		"downstream should not receive more than 1MB of body data")

	// Audit should still log with unknownValue tool name (body was too large to parse).
	assert.Equal(t, 1, store.Count())
	entries, _ := store.List(0, 1)
	require.Len(t, entries, 1)
	assert.Equal(t, unknownValue, entries[0].ToolName)
}

func TestAuditMiddleware_OversizedBodyRestoredForDownstream(t *testing.T) {
	t.Parallel()

	mw, _, _ := newTestMiddleware(t)

	var downstreamBodySize int
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		downstreamBodySize = len(body)
		w.WriteHeader(http.StatusOK)
	})

	handler := mw.Handler(inner)

	// 1MB + 1 byte: audit middleware reads up to 1MB then fails.
	// The partial 1MB body must be restored for downstream to read.
	oversizedBody := strings.Repeat("x", 1<<20+1)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Downstream should receive the partial body (up to 1MB), not an empty body.
	// This ensures downstream can generate the correct error response.
	assert.Equal(t, 1<<20, downstreamBodySize,
		"partial body must be restored for downstream processing")
}
