// Package integration provides end-to-end tests for the secure-mcp-gateway.
// These tests verify the full request flow: Proxy -> Token Verification -> Audit Logging.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akaitigo/secure-mcp-gateway/internal/audit"
	"github.com/akaitigo/secure-mcp-gateway/internal/auth"
	"github.com/akaitigo/secure-mcp-gateway/internal/proxy"
	"github.com/akaitigo/secure-mcp-gateway/internal/testutil"
)

// testGateway encapsulates a fully wired gateway (proxy + auth + audit) for integration tests.
type testGateway struct {
	cleanup    func()
	auditStore *audit.Store
	proxyURL   string
}

// newTestGateway creates a gateway with the full middleware chain:
// RequestID -> Audit -> Auth -> Proxy -> Upstream MCP mock.
func newTestGateway(
	t *testing.T,
	hydraServer *httptest.Server,
	upstreamServer *httptest.Server,
) *testGateway {
	t.Helper()

	// Set up audit components.
	auditStore := audit.NewStore()
	var auditBuf bytes.Buffer
	auditLogger := audit.NewLoggerWithWriter(&auditBuf, auditStore)
	auditMiddleware := audit.NewMiddleware(auditLogger,
		audit.WithSkipPaths("/health"),
	)

	// Set up auth middleware using mock Hydra.
	introspector, err := auth.NewHydraIntrospector(hydraServer.URL, nil)
	require.NoError(t, err)
	authMiddleware := auth.NewMiddleware(introspector,
		auth.WithSkipPaths("/health"),
		auth.WithMiddlewareLogger(slog.New(slog.NewJSONHandler(io.Discard, nil))),
	)

	// Build proxy with full middleware chain.
	// Middleware order (outermost to innermost):
	//   RequestID -> Audit -> Auth -> Proxy handler
	// Audit wraps Auth so that both ALLOW and DENY decisions are logged.
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv, err := proxy.New(":0", upstreamServer.URL,
		proxy.WithLogger(logger),
		proxy.WithMiddleware(audit.RequestIDMiddleware),
		proxy.WithMiddleware(auditMiddleware.Handler),
		proxy.WithMiddleware(authMiddleware.Handler),
	)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	go func() {
		_ = srv.Serve(ln)
	}()

	proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())

	cleanup := func() {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		hydraServer.Close()
		upstreamServer.Close()
	}

	return &testGateway{
		proxyURL:   proxyURL,
		auditStore: auditStore,
		cleanup:    cleanup,
	}
}

// newMockUpstream creates a mock MCP server that echoes back the JSON-RPC method.
func newMockUpstream() *httptest.Server {
	return testutil.NewMockMCPServer(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(bodyBytes, &req)

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]interface{}{
				"output": "success",
				"method": req["method"],
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// TestIntegration_ValidToken_AllowAndAuditLog verifies the full E2E flow:
// valid token -> upstream forwarding -> 200 OK -> audit log records ALLOW.
func TestIntegration_ValidToken_AllowAndAuditLog(t *testing.T) {
	t.Parallel()

	const (
		validToken = "valid-test-token-12345"
		clientID   = "test-ai-agent"
	)

	hydra := testutil.NewMockHydraServerWithTokenValidation(validToken, clientID)
	upstream := newMockUpstream()
	gw := newTestGateway(t, hydra, upstream)
	defer gw.cleanup()

	// Send a valid tools/call request with a valid Bearer token.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db-query"}}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify upstream response was proxied successfully.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)
	assert.Equal(t, "2.0", rpcResp["jsonrpc"])

	result, ok := rpcResp["result"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "success", result["output"])

	// Verify X-Request-Id was set in response.
	requestID := resp.Header.Get("X-Request-Id")
	assert.NotEmpty(t, requestID, "X-Request-Id header should be set")

	// Verify audit log recorded ALLOW with correct client_id and tool_name.
	entries, total := gw.auditStore.List(0, 10)
	require.Equal(t, 1, total, "exactly one audit entry should be recorded")
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, clientID, entry.ClientID)
	assert.Equal(t, "tools/call", entry.ToolName)
	assert.Equal(t, audit.DecisionAllow, entry.Decision)
	assert.NotEmpty(t, entry.RequestID)
	assert.NotEmpty(t, entry.Timestamp)
}

// TestIntegration_InvalidToken_DenyAndAuditLog verifies the deny flow:
// invalid token -> 401 Unauthorized -> audit log records DENY.
func TestIntegration_InvalidToken_DenyAndAuditLog(t *testing.T) {
	t.Parallel()

	const (
		validToken   = "valid-test-token-67890"
		invalidToken = "invalid-token-xyz"
		clientID     = "test-ai-agent"
	)

	hydra := testutil.NewMockHydraServerWithTokenValidation(validToken, clientID)
	upstream := newMockUpstream()
	gw := newTestGateway(t, hydra, upstream)
	defer gw.cleanup()

	// Send a tools/call request with an INVALID Bearer token.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secret-tool"}}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+invalidToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify 401 Unauthorized was returned.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify WWW-Authenticate header is set per RFC 7235.
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")

	// Verify audit log recorded DENY.
	entries, total := gw.auditStore.List(0, 10)
	require.Equal(t, 1, total, "exactly one audit entry should be recorded")
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "unknown", entry.ClientID, "client_id should be 'unknown' for invalid tokens")
	assert.Equal(t, "tools/call", entry.ToolName)
	assert.Equal(t, audit.DecisionDeny, entry.Decision)
	assert.NotEmpty(t, entry.RequestID)
}

// TestIntegration_MissingToken_DenyAndAuditLog verifies that requests
// without an Authorization header are denied and logged.
func TestIntegration_MissingToken_DenyAndAuditLog(t *testing.T) {
	t.Parallel()

	hydra := testutil.NewMockHydraServer(true, "any-client")
	upstream := newMockUpstream()
	gw := newTestGateway(t, hydra, upstream)
	defer gw.cleanup()

	// Send a request without any Authorization header.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify audit log recorded DENY.
	entries, total := gw.auditStore.List(0, 10)
	require.Equal(t, 1, total)

	entry := entries[0]
	assert.Equal(t, audit.DecisionDeny, entry.Decision)
	assert.Equal(t, "tools/list", entry.ToolName)
}

// TestIntegration_HealthEndpoint_BypassesAuthAndAudit verifies that the /health
// endpoint is not subject to auth or audit middleware.
func TestIntegration_HealthEndpoint_BypassesAuthAndAudit(t *testing.T) {
	t.Parallel()

	hydra := testutil.NewMockHydraServer(false, "")
	upstream := newMockUpstream()
	gw := newTestGateway(t, hydra, upstream)
	defer gw.cleanup()

	// Hit /health without any auth token.
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gw.proxyURL+"/health", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])

	// Verify NO audit entry was created for /health.
	assert.Equal(t, 0, gw.auditStore.Count(), "health endpoint should not create audit entries")
}

// TestIntegration_MultipleRequests_AuditLogOrder verifies that multiple requests
// produce audit entries in the correct order (newest first).
func TestIntegration_MultipleRequests_AuditLogOrder(t *testing.T) {
	t.Parallel()

	const (
		validToken = "multi-test-token"
		clientID   = "multi-agent"
	)

	hydra := testutil.NewMockHydraServerWithTokenValidation(validToken, clientID)
	upstream := newMockUpstream()
	gw := newTestGateway(t, hydra, upstream)
	defer gw.cleanup()

	methods := []string{"tools/list", "tools/call", "resources/read"}

	for _, method := range methods {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"%s"}`, method)
		ctx := t.Context()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.proxyURL+"/",
			strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+validToken)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// Verify all 3 requests are logged.
	entries, total := gw.auditStore.List(0, 10)
	require.Equal(t, 3, total)
	require.Len(t, entries, 3)

	// Entries are newest-first, so reverse order of methods.
	assert.Equal(t, "resources/read", entries[0].ToolName)
	assert.Equal(t, "tools/call", entries[1].ToolName)
	assert.Equal(t, "tools/list", entries[2].ToolName)

	// All should be ALLOW.
	for _, e := range entries {
		assert.Equal(t, audit.DecisionAllow, e.Decision)
		assert.Equal(t, clientID, e.ClientID)
	}
}

// TestIntegration_RequestID_Propagation verifies that X-Request-Id is generated
// and propagated through the middleware chain, and appears in audit entries.
func TestIntegration_RequestID_Propagation(t *testing.T) {
	t.Parallel()

	const (
		validToken = "reqid-test-token"
		clientID   = "reqid-agent"
		customID   = "custom-request-id-abc-123"
	)

	hydra := testutil.NewMockHydraServerWithTokenValidation(validToken, clientID)
	upstream := newMockUpstream()
	gw := newTestGateway(t, hydra, upstream)
	defer gw.cleanup()

	// Test 1: Auto-generated request ID.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	autoID := resp.Header.Get("X-Request-Id")
	assert.NotEmpty(t, autoID, "auto-generated request ID should be set")

	// Test 2: Client-provided request ID.
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+validToken)
	req2.Header.Set("X-Request-Id", customID)

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()

	assert.Equal(t, customID, resp2.Header.Get("X-Request-Id"),
		"client-provided request ID should be echoed back")

	// Verify audit entries have request IDs.
	entries, total := gw.auditStore.List(0, 10)
	require.Equal(t, 2, total)

	// Newest first: custom ID entry is entries[0].
	assert.Equal(t, customID, entries[0].RequestID)
	assert.NotEmpty(t, entries[1].RequestID)
}
