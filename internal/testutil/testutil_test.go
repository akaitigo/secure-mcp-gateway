package testutil_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akaitigo/secure-mcp-gateway/internal/testutil"
)

func TestNewJSONRPCRequest(t *testing.T) {
	t.Parallel()

	reader := testutil.NewJSONRPCRequest(t, "tools/list", nil)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)

	var req testutil.JSONRPCRequest
	err = json.Unmarshal(body, &req)
	require.NoError(t, err)

	assert.Equal(t, "2.0", req.JSONRPC)
	assert.Equal(t, 1, req.ID)
	assert.Equal(t, "tools/list", req.Method)
}

func TestNewJSONRPCRequestWithParams(t *testing.T) {
	t.Parallel()

	params := map[string]string{"name": "test-tool"}
	reader := testutil.NewJSONRPCRequest(t, "tools/call", params)
	body, err := io.ReadAll(reader)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(body, &raw)
	require.NoError(t, err)

	p, ok := raw["params"].(map[string]interface{})
	require.True(t, ok, "params should be a map")
	assert.Equal(t, "test-tool", p["name"])
}

func TestParseJSONRPCResponse(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  map[string]string{"status": "ok"},
	}

	err := json.NewEncoder(recorder).Encode(resp)
	require.NoError(t, err)

	parsed := testutil.ParseJSONRPCResponse(t, recorder)
	assert.Equal(t, "2.0", parsed.JSONRPC)
	assert.Equal(t, 1, parsed.ID)
	assert.Nil(t, parsed.Error)
	assert.NotNil(t, parsed.Result)
}

func TestNewMockHydraServerActive(t *testing.T) {
	t.Parallel()

	server := testutil.NewMockHydraServer(true, "test-client")
	defer server.Close()

	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/admin/oauth2/introspect", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, true, result["active"])
	assert.Equal(t, "test-client", result["client_id"])
}

func TestNewMockHydraServerInactive(t *testing.T) {
	t.Parallel()

	server := testutil.NewMockHydraServer(false, "")
	defer server.Close()

	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/admin/oauth2/introspect", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, false, result["active"])
}

func TestNewMockMCPServer(t *testing.T) {
	t.Parallel()

	server := testutil.NewMockMCPServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		require.NoError(t, err)
	})
	defer server.Close()

	ctx := t.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
