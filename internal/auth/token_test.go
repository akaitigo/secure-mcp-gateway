package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractBearerToken_Valid(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer valid-token-123")

	token, err := extractBearerToken(r)
	require.NoError(t, err)
	assert.Equal(t, "valid-token-123", token)
}

func TestExtractBearerToken_MissingHeader(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := extractBearerToken(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing Authorization header")
}

func TestExtractBearerToken_NonBearerScheme(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	_, err := extractBearerToken(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization header must use Bearer scheme")
}

func TestExtractBearerToken_EmptyToken(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer ")

	_, err := extractBearerToken(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty Bearer token")
}

func TestExtractBearerToken_TooLong(t *testing.T) {
	t.Parallel()

	longToken := strings.Repeat("a", maxTokenLength+1)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+longToken)

	_, err := extractBearerToken(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum length")
}

func TestExtractBearerToken_InvalidCharacters(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer token\x00value")

	_, err := extractBearerToken(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid characters")
}

func TestExtractBearerToken_MaxLength(t *testing.T) {
	t.Parallel()

	exactMaxToken := strings.Repeat("a", maxTokenLength)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+exactMaxToken)

	token, err := extractBearerToken(r)
	require.NoError(t, err)
	assert.Equal(t, exactMaxToken, token)
}

func TestHydraIntrospector_ActiveToken(t *testing.T) {
	t.Parallel()

	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/admin/oauth2/introspect", r.URL.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "test-token", r.FormValue("token"))

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"active":    true,
			"client_id": "my-client",
			"scope":     "tools:read tools:call",
			"exp":       1234567890,
		}
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer hydra.Close()

	introspector, err := NewHydraIntrospector(hydra.URL, nil)
	require.NoError(t, err)

	result, err := introspector.Introspect(t.Context(), "test-token")
	require.NoError(t, err)
	assert.True(t, result.Active)
	assert.Equal(t, "my-client", result.ClientID)
	assert.Equal(t, "tools:read tools:call", result.Scope)
}

func TestHydraIntrospector_InactiveToken(t *testing.T) {
	t.Parallel()

	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"active": false,
		}
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer hydra.Close()

	introspector, err := NewHydraIntrospector(hydra.URL, nil)
	require.NoError(t, err)

	result, err := introspector.Introspect(t.Context(), "expired-token")
	require.NoError(t, err)
	assert.False(t, result.Active)
}

func TestHydraIntrospector_ServerError(t *testing.T) {
	t.Parallel()

	hydra := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer hydra.Close()

	introspector, err := NewHydraIntrospector(hydra.URL, nil)
	require.NoError(t, err)

	_, err = introspector.Introspect(t.Context(), "test-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestHydraIntrospector_InvalidURL(t *testing.T) {
	t.Parallel()

	_, err := NewHydraIntrospector("", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestHydraIntrospector_MalformedURL(t *testing.T) {
	t.Parallel()

	_, err := NewHydraIntrospector("not-a-url", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestHydraIntrospector_NetworkError(t *testing.T) {
	t.Parallel()

	introspector, err := NewHydraIntrospector("http://localhost:1", nil)
	require.NoError(t, err)

	_, err = introspector.Introspect(t.Context(), "test-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "introspection request failed")
}

func TestTokenInfoContext(t *testing.T) {
	t.Parallel()

	info := &TokenInfo{
		ClientID: "client-123",
		Scopes:   []string{"tools:read", "tools:call"},
	}

	ctx := WithTokenInfo(t.Context(), info)
	retrieved := GetTokenInfo(ctx)

	require.NotNil(t, retrieved)
	assert.Equal(t, "client-123", retrieved.ClientID)
	assert.Equal(t, []string{"tools:read", "tools:call"}, retrieved.Scopes)
}

func TestGetTokenInfo_Empty(t *testing.T) {
	t.Parallel()

	retrieved := GetTokenInfo(t.Context())
	assert.Nil(t, retrieved)
}

func TestParseScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{name: "multiple scopes", input: "tools:read tools:call", expected: []string{"tools:read", "tools:call"}},
		{name: "single scope", input: "tools:read", expected: []string{"tools:read"}},
		{name: "empty", input: "", expected: nil},
		{name: "extra spaces", input: "  tools:read   tools:call  ", expected: []string{"tools:read", "tools:call"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, parseScopes(tt.input))
		})
	}
}
