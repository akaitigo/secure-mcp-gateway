package proxy_test

import (
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

	"github.com/akaitigo/secure-mcp-gateway/internal/proxy"
)

// newTestProxy creates a proxy server pointing at the given upstream URL.
// It returns the proxy's URL and a cleanup function.
func newTestProxy(t *testing.T, upstreamURL string) (string, func()) {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv, err := proxy.New(":0", upstreamURL, proxy.WithLogger(logger))
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
	}

	return proxyURL, cleanup
}

func TestHealth(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL+"/health", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
}

func TestProxy_ForwardJSONRPCRequest(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req map[string]interface{}
		err = json.Unmarshal(bodyBytes, &req)
		require.NoError(t, err)

		assert.Equal(t, "tools/list", req["method"])

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{"tools": []string{}},
		}
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)
	assert.Equal(t, "2.0", rpcResp["jsonrpc"])
}

func TestProxy_ToolsCallForwarding(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req map[string]interface{}
		err = json.Unmarshal(bodyBytes, &req)
		require.NoError(t, err)

		assert.Equal(t, "tools/call", req["method"])

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{"output": "tool executed"},
		}
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test-tool"}}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)

	result, ok := rpcResp["result"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "tool executed", result["output"])
}

func TestProxy_InvalidContentType(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)

	errObj, ok := rpcResp["error"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, errObj["message"], "Content-Type")
}

func TestProxy_InvalidJSONRPC(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)

	errObj, ok := rpcResp["error"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, errObj["message"], "2.0")
}

func TestProxy_MalformedJSON(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{invalid json`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)

	errObj, ok := rpcResp["error"].(map[string]interface{})
	require.True(t, ok)
	code := errObj["code"].(float64)
	assert.Equal(t, float64(-32700), code) // Parse error
}

func TestProxy_RequestBodyTooLarge(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	// Create a body larger than 1MB.
	largeBody := strings.Repeat("x", 1<<20+1)
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(largeBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)

	errObj, ok := rpcResp["error"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, errObj["message"], "1MB")
}

func TestProxy_UpstreamUnavailable(t *testing.T) {
	t.Parallel()

	// Use a URL that won't be listening.
	proxyURL, cleanup := newTestProxy(t, "http://localhost:1")
	defer cleanup()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)

	errObj, ok := rpcResp["error"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, errObj["message"], "upstream server unavailable")
}

func TestProxy_GracefulShutdown(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv, err := proxy.New(":0", upstream.URL, proxy.WithLogger(logger))
	require.NoError(t, err)

	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	go func() {
		_ = srv.Serve(ln)
	}()

	// Give server a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Shutdown should succeed without errors.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	err = srv.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestProxy_SSERequest(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"event\":\"test\"}\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL+"/sse", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "data: ")
}

func TestNew_InvalidUpstreamURL(t *testing.T) {
	t.Parallel()

	_, err := proxy.New(":0", "not-a-valid-url")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid upstream MCP URL")
}

func TestProxy_MissingMethod(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{"jsonrpc":"2.0","id":1}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var rpcResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&rpcResp)
	require.NoError(t, err)

	errObj, ok := rpcResp["error"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, errObj["message"], "method")
}

func TestProxy_MethodLogging(t *testing.T) {
	t.Parallel()

	var receivedMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req map[string]interface{}
		err = json.Unmarshal(bodyBytes, &req)
		require.NoError(t, err)

		receivedMethod, _ = req["method"].(string)

		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{},
		})
		require.NoError(t, err)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db-query"}}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "tools/call", receivedMethod)
}

func TestProxy_QueryStringForwarding(t *testing.T) {
	t.Parallel()

	var receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{},
		})
		require.NoError(t, err)
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		proxyURL+"/mcp?cursor=abc&transport=sse",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, receivedQuery, "cursor=abc")
	assert.Contains(t, receivedQuery, "transport=sse")
}

func TestProxy_SSEQueryStringForwarding(t *testing.T) {
	t.Parallel()

	var receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"event\":\"test\"}\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer upstream.Close()

	proxyURL, cleanup := newTestProxy(t, upstream.URL)
	defer cleanup()

	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		proxyURL+"/sse?cursor=xyz&transport=sse", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, receivedQuery, "cursor=xyz")
	assert.Contains(t, receivedQuery, "transport=sse")
}
