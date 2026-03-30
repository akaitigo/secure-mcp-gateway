package audit

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/akaitigo/secure-mcp-gateway/internal/auth"
	"github.com/akaitigo/secure-mcp-gateway/internal/jsonrpc"
)

// unknownValue is the fallback used when client ID or tool name cannot be determined.
const unknownValue = "unknown"

// Middleware provides HTTP middleware for audit logging of MCP tool invocations.
type Middleware struct {
	logger    *Logger
	skipPaths map[string]bool
}

// MiddlewareOption configures the audit Middleware.
type MiddlewareOption func(*Middleware)

// WithSkipPaths sets paths that bypass audit logging (e.g., "/health").
func WithSkipPaths(paths ...string) MiddlewareOption {
	return func(m *Middleware) {
		for _, p := range paths {
			m.skipPaths[p] = true
		}
	}
}

// NewMiddleware creates a new audit middleware.
func NewMiddleware(logger *Logger, opts ...MiddlewareOption) *Middleware {
	m := &Middleware{
		logger:    logger,
		skipPaths: make(map[string]bool),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// statusRecorder captures the HTTP status code written by downstream handlers.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Handler wraps the given handler with audit logging.
// It records tool invocations with client_id, tool_name, decision, and request_id.
// Sensitive information (tokens, request bodies) is never logged.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip audit for configured paths (e.g., /health).
		if m.skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Only audit POST requests (JSON-RPC method calls).
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		// Read body to extract tool name, then restore it for downstream.
		toolName := extractToolName(r)

		// Wrap response writer to capture status code.
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Determine decision based on response status.
		decision := DecisionAllow
		if rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden {
			decision = DecisionDeny
		}

		// Extract client_id from context (set by auth middleware).
		clientID := unknownValue
		if info := auth.GetTokenInfo(r.Context()); info != nil {
			clientID = info.ClientID
		}

		// Get request ID from context (set by RequestIDMiddleware).
		requestID := GetRequestID(r.Context())

		metadata := map[string]string{
			"http_method": r.Method,
			"path":        r.URL.Path,
			"remote_addr": r.RemoteAddr,
			"status_code": http.StatusText(rec.status),
		}

		entry := NewEntry(clientID, toolName, decision, requestID, metadata)
		m.logger.Log(entry)
	})
}

// extractToolName reads the JSON-RPC request body to extract the method name.
// It restores the body so downstream handlers can read it again.
func extractToolName(r *http.Request) string {
	if r.Body == nil {
		return unknownValue
	}

	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return unknownValue
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return unknownValue
	}
	// Restore body for downstream handlers.
	r.Body = io.NopCloser(bytes.NewReader(body))

	req, err := jsonrpc.Parse(body)
	if err != nil {
		return unknownValue
	}
	return req.Method
}
