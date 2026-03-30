package jsonrpc_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akaitigo/secure-mcp-gateway/internal/jsonrpc"
)

func TestParse_ValidRequest(t *testing.T) {
	t.Parallel()

	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req, err := jsonrpc.Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "2.0", req.JSONRPC)
	assert.Equal(t, "tools/list", req.Method)
}

func TestParse_ValidRequestWithParams(t *testing.T) {
	t.Parallel()

	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test-tool"}}`)
	req, err := jsonrpc.Parse(data)
	require.NoError(t, err)

	assert.Equal(t, "tools/call", req.Method)
	assert.NotNil(t, req.Params)
}

func TestParse_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := jsonrpc.Parse([]byte(`{invalid`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestParse_WrongVersion(t *testing.T) {
	t.Parallel()

	data := []byte(`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`)
	_, err := jsonrpc.Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2.0")
}

func TestParse_MissingMethod(t *testing.T) {
	t.Parallel()

	data := []byte(`{"jsonrpc":"2.0","id":1}`)
	_, err := jsonrpc.Parse(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "method")
}

func TestNewErrorResponse(t *testing.T) {
	t.Parallel()

	id := json.RawMessage(`1`)
	resp := jsonrpc.NewErrorResponse(id, jsonrpc.CodeParseError, "parse error")

	assert.Equal(t, "2.0", resp.JSONRPC)
	require.NotNil(t, resp.Error)
	assert.Equal(t, jsonrpc.CodeParseError, resp.Error.Code)
	assert.Equal(t, "parse error", resp.Error.Message)
}

func TestResponse_Marshal(t *testing.T) {
	t.Parallel()

	resp := jsonrpc.NewErrorResponse(json.RawMessage(`1`), jsonrpc.CodeInternalError, "internal error")
	data, err := resp.Marshal()
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "2.0", parsed["jsonrpc"])
}
