package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/akaitigo/secure-mcp-gateway/internal/auth"
	"github.com/akaitigo/secure-mcp-gateway/internal/jsonrpc"
)

// maxRequestSize is the maximum allowed request body size (1MB).
// This mirrors the limit enforced by the proxy and audit middleware.
const maxRequestSize = 1 << 20

// toolCallMethod is the JSON-RPC method for MCP tool invocations.
const toolCallMethod = "tools/call"

// Middleware provides HTTP middleware that enforces OPA policy decisions
// for MCP tool invocations. It must run after the auth middleware so that
// the authenticated client identity is available in the request context.
//
// Failure semantics are fail-close: when the policy engine is unreachable
// or returns an unexpected response, the request is denied with 403.
type Middleware struct {
	evaluator Evaluator
	logger    *slog.Logger
	skipPaths map[string]bool
}

// MiddlewareOption configures the policy Middleware.
type MiddlewareOption func(*Middleware)

// WithMiddlewareLogger sets a custom logger for the middleware.
func WithMiddlewareLogger(logger *slog.Logger) MiddlewareOption {
	return func(m *Middleware) {
		m.logger = logger
	}
}

// WithSkipPaths sets paths that bypass policy evaluation (e.g., "/health").
func WithSkipPaths(paths ...string) MiddlewareOption {
	return func(m *Middleware) {
		for _, p := range paths {
			m.skipPaths[p] = true
		}
	}
}

// NewMiddleware creates a new policy middleware with the given evaluator.
func NewMiddleware(evaluator Evaluator, opts ...MiddlewareOption) *Middleware {
	m := &Middleware{
		evaluator: evaluator,
		logger:    slog.Default(),
		skipPaths: make(map[string]bool),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Handler wraps the given handler with OPA policy enforcement.
//
// Only JSON-RPC POST requests carry tool invocations and are evaluated.
// Non-POST requests (e.g., GET for SSE stream setup) do not invoke tools
// and pass through; they have already passed token verification.
// Malformed JSON-RPC bodies pass through so the proxy handler can return
// the proper JSON-RPC error response without forwarding upstream.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip policy evaluation for configured paths.
		if m.skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		input, proceed := m.buildInput(w, r)
		if input == nil {
			if proceed {
				next.ServeHTTP(w, r)
			}
			return
		}

		allowed, err := m.evaluator.Evaluate(r.Context(), input)
		if err != nil {
			// Fail-close: deny when the policy engine is unreachable or
			// returns an unexpected response. A security gateway must never
			// fail open.
			m.logger.Error(
				"policy evaluation failed, denying request (fail-close)",
				"error", err.Error(),
				"client_id", input.ClientID,
				"method", input.Method,
				"tool_name", input.ToolName,
				"remote_addr", r.RemoteAddr,
			)
			writeForbidden(w, "policy evaluation unavailable")
			return
		}

		if !allowed {
			m.logger.Warn(
				"request denied by policy",
				"client_id", input.ClientID,
				"method", input.Method,
				"tool_name", input.ToolName,
				"remote_addr", r.RemoteAddr,
			)
			writeForbidden(w, "denied by policy")
			return
		}

		m.logger.Debug(
			"request allowed by policy",
			"client_id", input.ClientID,
			"method", input.Method,
			"tool_name", input.ToolName,
		)
		next.ServeHTTP(w, r)
	})
}

// buildInput parses the JSON-RPC request body and builds the policy input.
// It returns (nil, true) when the request should pass through to the next
// handler without policy evaluation (non-JSON or malformed bodies that the
// proxy handler will reject itself), and (input, false) when evaluation is
// required. An empty body yields an input with an empty method, which the
// default-deny policy rejects, so bodyless POSTs cannot bypass evaluation.
func (m *Middleware) buildInput(w http.ResponseWriter, r *http.Request) (*Input, bool) {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		// The proxy handler rejects non-JSON POSTs with a JSON-RPC error.
		return nil, true
	}

	body, ok := m.readBody(w, r)
	if !ok {
		// Oversized body: the proxy handler returns the size-limit error.
		return nil, true
	}

	input := &Input{}
	if info := auth.GetTokenInfo(r.Context()); info != nil {
		input.ClientID = info.ClientID
		input.Scopes = info.Scopes
	}

	if len(body) == 0 {
		// No JSON-RPC payload: evaluate with an empty method so the
		// default-deny policy applies instead of forwarding upstream.
		return input, false
	}

	req, err := jsonrpc.Parse(body)
	if err != nil {
		// The proxy handler rejects malformed JSON-RPC with a parse error
		// and never forwards it upstream.
		return nil, true
	}

	input.Method = req.Method
	input.ToolName = extractToolName(req)
	return input, false
}

// readBody reads and restores the request body, enforcing the size limit.
// It returns the body bytes and whether the read succeeded.
func (m *Middleware) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}

	// Enforce the body size limit before io.ReadAll to prevent memory
	// exhaustion from oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	body, readErr := io.ReadAll(r.Body)
	// Always restore whatever was read so downstream handlers can still
	// process or correctly reject the request.
	r.Body = io.NopCloser(bytes.NewReader(body))
	if readErr != nil {
		return nil, false
	}
	return body, true
}

// extractToolName extracts the tool name from a "tools/call" request's params.
// Returns an empty string for other methods or when params are malformed.
func extractToolName(req *jsonrpc.Request) string {
	if req.Method != toolCallMethod || len(req.Params) == 0 {
		return ""
	}

	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return ""
	}
	return params.Name
}

// writeForbidden writes a 403 response with a JSON error body.
func writeForbidden(w http.ResponseWriter, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	resp := struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}{
		Error:   "forbidden",
		Message: description,
	}
	//nolint:errcheck // best-effort write to response
	json.NewEncoder(w).Encode(resp)
}
