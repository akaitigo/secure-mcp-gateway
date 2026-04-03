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

// maxRequestSize is the maximum allowed request body size (1MB).
// This must be enforced before any io.ReadAll to prevent memory
// exhaustion from oversized payloads.
const maxRequestSize = 1 << 20

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

// AuditClientIDHeader is an internal header used to propagate client_id
// from auth middleware to audit middleware across middleware boundaries.
// This header is stripped from the final response and never sent to clients.
const AuditClientIDHeader = "X-Audit-Client-Id"

// statusRecorder captures the HTTP status code written by downstream handlers.
// It also implements http.Flusher to support SSE streaming through the
// audit middleware without breaking the Flush interface.
type statusRecorder struct {
	http.ResponseWriter
	clientID string // captured from internal header before stripping
	status   int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	// Capture and strip internal audit header before committing headers
	// to the client. This ensures X-Audit-Client-Id is never exposed to
	// external callers while preserving the value for audit logging.
	if id := r.ResponseWriter.Header().Get(AuditClientIDHeader); id != "" {
		r.clientID = id
	}
	r.ResponseWriter.Header().Del(AuditClientIDHeader)
	r.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying ResponseWriter if it supports http.Flusher.
// This is essential for SSE streaming which relies on flushing to push events.
func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Handler wraps the given handler with audit logging.
// It records tool invocations with client_id, tool_name, decision, and request_id.
// Sensitive information (tokens, request bodies) is never logged.
//
// When placed outside the auth middleware, client_id is obtained from the
// X-Audit-Client-Id internal header set by the auth middleware.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip audit for configured paths (e.g., /health).
		if m.skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// For POST requests, extract tool name from JSON-RPC body.
		// For non-POST requests (e.g., GET/SSE), log the request with
		// the HTTP method + path as tool name.
		var toolName string
		if r.Method == http.MethodPost {
			// Enforce body size limit before any io.ReadAll to prevent
			// memory exhaustion. Without this, an attacker could send an
			// arbitrarily large body that extractToolName would fully buffer.
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

			// Read body to extract tool name, then restore it for downstream.
			toolName = extractToolName(r)
		} else {
			// Non-POST requests (SSE connections, etc.) do not carry
			// a JSON-RPC body, so use HTTP method + path for traceability.
			toolName = truncate(r.Method+" "+r.URL.Path, maxHeaderValueLen)
		}

		// Wrap response writer to capture status code and strip internal headers.
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Determine client_id: prefer the value captured by statusRecorder
		// from the internal header (set by auth middleware and stripped in
		// WriteHeader), then fall back to request context.
		clientID := unknownValue
		if rec.clientID != "" {
			clientID = rec.clientID
		} else if info := auth.GetTokenInfo(r.Context()); info != nil {
			clientID = info.ClientID
		}

		// Determine decision based on response status.
		decision := DecisionAllow
		if rec.status == http.StatusUnauthorized || rec.status == http.StatusForbidden {
			decision = DecisionDeny
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
	return truncate(req.Method, maxHeaderValueLen)
}

// truncate returns s truncated to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
