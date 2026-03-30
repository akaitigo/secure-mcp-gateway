// Package testutil provides shared test helpers for secure-mcp-gateway.
package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// JSONRPCRequest represents a JSON-RPC 2.0 request for testing.
type JSONRPCRequest struct {
	Params  interface{} `json:"params,omitempty"`
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	ID      int         `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response for testing.
type JSONRPCResponse struct {
	Error   *JSONRPCError   `json:"error,omitempty"`
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	ID      int             `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error.
type JSONRPCError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// NewJSONRPCRequest creates a new JSON-RPC 2.0 request body as an io.Reader.
func NewJSONRPCRequest(t *testing.T, method string, params interface{}) io.Reader {
	t.Helper()

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	require.NoError(t, err, "failed to marshal JSON-RPC request")

	return strings.NewReader(string(body))
}

// ParseJSONRPCResponse parses a JSON-RPC 2.0 response from the recorder.
func ParseJSONRPCResponse(t *testing.T, recorder *httptest.ResponseRecorder) JSONRPCResponse {
	t.Helper()

	var resp JSONRPCResponse
	err := json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err, "failed to decode JSON-RPC response")

	return resp
}

// NewMockMCPServer creates a mock MCP server that responds with the given handler.
func NewMockMCPServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// NewMockHydraServer creates a mock ORY Hydra introspection endpoint.
// If active is true, the token is valid; otherwise, it returns an inactive response.
func NewMockHydraServer(active bool, clientID string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		resp := map[string]interface{}{
			"active": active,
		}
		if active {
			resp["client_id"] = clientID
			resp["scope"] = "tools:read tools:call"
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))
}

// SetEnv sets an environment variable for the duration of the test.
func SetEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}
