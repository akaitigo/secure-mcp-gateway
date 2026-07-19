package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockOPA creates a mock OPA server that records the received input
// and responds with the given raw JSON body and status code.
func newMockOPA(t *testing.T, status int, responseBody string, capture *Input) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/data/gateway/authz/allow", r.URL.Path)

		if capture != nil {
			var payload struct {
				Input *Input `json:"input"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			require.NotNil(t, payload.Input)
			*capture = *payload.Input
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(responseBody))
	}))
}

func TestNewClient_EmptyURL(t *testing.T) {
	t.Parallel()

	_, err := NewClient("", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OPA URL is required")
}

func TestNewClient_InvalidURL(t *testing.T) {
	t.Parallel()

	_, err := NewClient("not-a-valid-url", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid OPA URL")
}

func TestClient_Evaluate_Allow(t *testing.T) {
	t.Parallel()

	var captured Input
	opa := newMockOPA(t, http.StatusOK, `{"result": true}`, &captured)
	defer opa.Close()

	client, err := NewClient(opa.URL, nil)
	require.NoError(t, err)

	input := &Input{
		ClientID: "test-client",
		Scopes:   []string{"tools:read", "tools:call"},
		Method:   "tools/call",
		ToolName: "db-query",
	}

	allowed, err := client.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.True(t, allowed)

	// Verify the full input document was sent to OPA.
	assert.Equal(t, "test-client", captured.ClientID)
	assert.Equal(t, []string{"tools:read", "tools:call"}, captured.Scopes)
	assert.Equal(t, "tools/call", captured.Method)
	assert.Equal(t, "db-query", captured.ToolName)
}

func TestClient_Evaluate_Deny(t *testing.T) {
	t.Parallel()

	opa := newMockOPA(t, http.StatusOK, `{"result": false}`, nil)
	defer opa.Close()

	client, err := NewClient(opa.URL, nil)
	require.NoError(t, err)

	allowed, err := client.Evaluate(context.Background(), &Input{Method: "tools/call"})
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestClient_Evaluate_UndefinedDecision(t *testing.T) {
	t.Parallel()

	// OPA returns {} when the decision document does not exist
	// (e.g., the policy is not loaded).
	opa := newMockOPA(t, http.StatusOK, `{}`, nil)
	defer opa.Close()

	client, err := NewClient(opa.URL, nil)
	require.NoError(t, err)

	allowed, err := client.Evaluate(context.Background(), &Input{Method: "tools/list"})
	require.ErrorIs(t, err, ErrDecisionUndefined)
	assert.False(t, allowed)
}

func TestClient_Evaluate_Non200Status(t *testing.T) {
	t.Parallel()

	opa := newMockOPA(t, http.StatusInternalServerError, `{"error": "boom"}`, nil)
	defer opa.Close()

	client, err := NewClient(opa.URL, nil)
	require.NoError(t, err)

	allowed, err := client.Evaluate(context.Background(), &Input{Method: "tools/list"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
	assert.False(t, allowed)
}

func TestClient_Evaluate_InvalidJSONResponse(t *testing.T) {
	t.Parallel()

	opa := newMockOPA(t, http.StatusOK, `not-json`, nil)
	defer opa.Close()

	client, err := NewClient(opa.URL, nil)
	require.NoError(t, err)

	allowed, err := client.Evaluate(context.Background(), &Input{Method: "tools/list"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode policy response")
	assert.False(t, allowed)
}

func TestClient_Evaluate_ConnectionError(t *testing.T) {
	t.Parallel()

	// Create and immediately close the server to get an unreachable URL.
	opa := newMockOPA(t, http.StatusOK, `{"result": true}`, nil)
	opa.Close()

	client, err := NewClient(opa.URL, nil)
	require.NoError(t, err)

	allowed, err := client.Evaluate(context.Background(), &Input{Method: "tools/list"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy evaluation request failed")
	assert.False(t, allowed)
}

func TestClient_Evaluate_TrailingSlashURL(t *testing.T) {
	t.Parallel()

	opa := newMockOPA(t, http.StatusOK, `{"result": true}`, nil)
	defer opa.Close()

	client, err := NewClient(opa.URL+"/", nil)
	require.NoError(t, err)

	allowed, err := client.Evaluate(context.Background(), &Input{Method: "tools/list"})
	require.NoError(t, err)
	assert.True(t, allowed)
}
