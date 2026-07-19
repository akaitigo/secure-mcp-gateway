package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akaitigo/secure-mcp-gateway/internal/auth"
)

// mockEvaluator implements Evaluator for testing.
type mockEvaluator struct {
	err     error
	decide  func(input *Input) bool
	inputs  []*Input
	allowed bool
}

func (m *mockEvaluator) Evaluate(_ context.Context, input *Input) (bool, error) {
	m.inputs = append(m.inputs, input)
	if m.err != nil {
		return false, m.err
	}
	if m.decide != nil {
		return m.decide(input), nil
	}
	return m.allowed, nil
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// echoHandler records that it was reached and echoes the request body.
func echoHandler(reached *bool, gotBody *string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		if gotBody != nil {
			body, _ := io.ReadAll(r.Body)
			*gotBody = string(body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}
}

// newToolCallRequest builds an authenticated JSON-RPC tools/call request.
func newToolCallRequest(toolName string) *http.Request {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + toolName + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	info := &auth.TokenInfo{
		ClientID: "test-client",
		Scopes:   []string{"tools:call"},
	}
	return req.WithContext(auth.WithTokenInfo(req.Context(), info))
}

func TestMiddleware_AllowedToolCall(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: true}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	var gotBody string
	handler := mw.Handler(echoHandler(&reached, &gotBody))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newToolCallRequest("db-query"))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached, "downstream handler should be reached for allowed calls")

	// Verify the policy input was built from token info and JSON-RPC body.
	require.Len(t, mock.inputs, 1)
	input := mock.inputs[0]
	assert.Equal(t, "test-client", input.ClientID)
	assert.Equal(t, []string{"tools:call"}, input.Scopes)
	assert.Equal(t, "tools/call", input.Method)
	assert.Equal(t, "db-query", input.ToolName)

	// Verify the body was restored for the downstream handler.
	assert.Contains(t, gotBody, `"db-query"`)
}

func TestMiddleware_DeniedToolCall(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newToolCallRequest("secret-tool"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), "forbidden")
	assert.Contains(t, rec.Body.String(), "denied by policy")
	assert.False(t, reached, "downstream handler must not be reached for denied calls")
}

func TestMiddleware_EvaluatorError_FailClose(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{err: errors.New("OPA is down")}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newToolCallRequest("db-query"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "policy evaluation unavailable")
	assert.False(t, reached, "requests must be denied when the policy engine fails (fail-close)")
}

func TestMiddleware_UndefinedDecision_FailClose(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{err: ErrDecisionUndefined}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newToolCallRequest("db-query"))

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, reached)
}

func TestMiddleware_SelectiveDecision(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{
		decide: func(input *Input) bool {
			return input.ToolName == "allowed-tool"
		},
	}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	// Allowed tool passes.
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, newToolCallRequest("allowed-tool"))
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Denied tool is rejected.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, newToolCallRequest("forbidden-tool"))
	assert.Equal(t, http.StatusForbidden, rec2.Code)
}

func TestMiddleware_SkipPath(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(
		mock,
		WithMiddlewareLogger(newTestLogger()),
		WithSkipPaths("/health"),
	)

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/health", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
	assert.Empty(t, mock.inputs, "evaluator should not be called for skip paths")
}

func TestMiddleware_NonPOSTPassesThrough(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached, "non-POST requests pass through (no tool invocation)")
	assert.Empty(t, mock.inputs)
}

func TestMiddleware_NonJSONContentTypePassesThrough(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("plain text"))
	req.Header.Set("Content-Type", "text/plain")
	handler.ServeHTTP(rec, req)

	// The proxy handler rejects non-JSON POSTs itself; policy passes through.
	assert.True(t, reached)
	assert.Empty(t, mock.inputs)
}

func TestMiddleware_MalformedJSONRPCPassesThrough(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	var gotBody string
	handler := mw.Handler(echoHandler(&reached, &gotBody))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{invalid-json`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	// The proxy handler rejects malformed JSON-RPC with a parse error and
	// never forwards it upstream; the body must be restored for it.
	assert.True(t, reached)
	assert.Equal(t, `{invalid-json`, gotBody)
	assert.Empty(t, mock.inputs)
}

func TestMiddleware_EmptyBodyIsEvaluated(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	// Empty-body POSTs must not bypass policy: they are evaluated with an
	// empty method, which the default-deny policy rejects.
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, reached)
	require.Len(t, mock.inputs, 1)
	assert.Empty(t, mock.inputs[0].Method)
}

func TestMiddleware_ToolNameOmittedForNonToolCall(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: true}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, mock.inputs, 1)
	assert.Equal(t, "tools/list", mock.inputs[0].Method)
	assert.Empty(t, mock.inputs[0].ToolName)
}

func TestMiddleware_MalformedParamsYieldsEmptyToolName(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"not-an-object"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	// Malformed params yield an empty tool name, which the default-deny
	// policy rejects.
	assert.Equal(t, http.StatusForbidden, rec.Code)
	require.Len(t, mock.inputs, 1)
	assert.Empty(t, mock.inputs[0].ToolName)
}

func TestMiddleware_MissingTokenInfoYieldsEmptyClientID(t *testing.T) {
	t.Parallel()

	mock := &mockEvaluator{allowed: false}
	mw := NewMiddleware(mock, WithMiddlewareLogger(newTestLogger()))

	var reached bool
	handler := mw.Handler(echoHandler(&reached, nil))

	rec := httptest.NewRecorder()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db-query"}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	require.Len(t, mock.inputs, 1)
	assert.Empty(t, mock.inputs[0].ClientID)
}
