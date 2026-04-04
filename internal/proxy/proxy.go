// Package proxy implements the MCP reverse proxy server that forwards
// JSON-RPC requests to an upstream MCP server and relays responses.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akaitigo/secure-mcp-gateway/internal/jsonrpc"
)

// maxRequestSize is the maximum allowed request body size (1MB).
const maxRequestSize = 1 << 20 // 1MB

// Middleware is a function that wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Server is the MCP reverse proxy server.
type Server struct {
	upstreamURL   *url.URL
	httpServer    *http.Server
	httpClient    *http.Client
	sseHTTPClient *http.Client // dedicated client for SSE (no timeout)
	logger        *slog.Logger
	middlewares   []Middleware
}

// Option configures the proxy server.
type Option func(*Server)

// WithLogger sets a custom logger for the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

// WithHTTPClient sets a custom HTTP client for upstream communication.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Server) {
		s.httpClient = client
	}
}

// WithMiddleware adds a middleware to the proxy server.
// Middlewares are applied in the order they are added.
func WithMiddleware(mw Middleware) Option {
	return func(s *Server) {
		s.middlewares = append(s.middlewares, mw)
	}
}

// New creates a new MCP proxy server.
func New(listenAddr, upstreamMCPURL string, opts ...Option) (*Server, error) {
	parsed, err := url.ParseRequestURI(upstreamMCPURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream MCP URL: %w", err)
	}

	s := &Server{
		upstreamURL: parsed,
		logger:      slog.Default(),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		// SSE connections are long-lived streams; a finite Timeout would kill
		// the connection mid-stream. Use Timeout=0 (no deadline) and rely on
		// the client's request context for cancellation.
		sseHTTPClient: &http.Client{
			Timeout: 0,
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/", s.handleProxy)

	// Apply middlewares in order (outermost first).
	var handler http.Handler = mux
	for i := len(s.middlewares) - 1; i >= 0; i-- {
		handler = s.middlewares[i](handler)
	}

	s.httpServer = &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout is intentionally 0 (disabled) to support long-lived
		// SSE streaming connections. Per-request timeouts are handled via
		// request context instead.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

// ListenAndServe starts the proxy server. It blocks until the server stops.
func (s *Server) ListenAndServe() error {
	s.logger.Info("proxy server starting",
		"addr", s.httpServer.Addr,
		"upstream", s.upstreamURL.String(),
	)
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// Serve starts the proxy server on the given listener. Useful for testing.
func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info("proxy server starting",
		"addr", ln.Addr().String(),
		"upstream", s.upstreamURL.String(),
	)
	if err := s.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("proxy server shutting down")
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the HTTP handler for testing purposes.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// handleHealth responds with a 200 OK for health checks.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		s.logger.Error("failed to write health response", "error", err)
	}
}

// nonSSEWriteTimeout is the write deadline applied to non-SSE requests.
// SSE (long-lived streaming) connections use no write timeout.
const nonSSEWriteTimeout = 30 * time.Second

// handleProxy routes MCP requests to the upstream server.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Check if this is an SSE request.
	if isSSERequest(r) {
		s.handleSSE(w, r)
		return
	}

	// Apply per-request write deadline for non-SSE requests.
	// The server-level WriteTimeout is 0 to support SSE streaming,
	// so we enforce timeouts on regular requests here.
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(nonSSEWriteTimeout)); err != nil {
		s.logger.Warn("failed to set write deadline", "error", err)
	}

	// Validate Content-Type for POST requests.
	if r.Method == http.MethodPost {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			s.writeJSONRPCError(w, jsonrpc.CodeInvalidRequest,
				"Content-Type must be application/json")
			return
		}
	}

	// Limit request body size.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		if isMaxBytesError(err) {
			s.writeJSONRPCError(w, jsonrpc.CodeInvalidRequest,
				"request body exceeds 1MB limit")
			return
		}
		s.writeJSONRPCError(w, jsonrpc.CodeParseError,
			"failed to read request body")
		return
	}

	// Parse and validate JSON-RPC request for POST.
	if r.Method == http.MethodPost && len(body) > 0 {
		req, parseErr := jsonrpc.Parse(body)
		if parseErr != nil {
			s.writeJSONRPCError(w, jsonrpc.CodeParseError, parseErr.Error())
			return
		}

		s.logger.Info("proxying MCP request",
			"method", req.Method,
			"remote_addr", r.RemoteAddr,
		)
	}

	s.forwardRequest(w, r, body)
}

// forwardRequest sends the request to the upstream MCP server.
func (s *Server) forwardRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	upstreamURL := s.upstreamURL.JoinPath(r.URL.Path)
	upstreamURL.RawQuery = r.URL.RawQuery

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = strings.NewReader(string(body))
	}

	// upstream URL is derived from a trusted server-side configuration value (UPSTREAM_MCP_URL),
	// not from user input. SSRF risk is mitigated by config validation in config.Load().
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bodyReader) //nolint:gosec // trusted config
	if err != nil {
		s.logger.Error("failed to create upstream request", "error", err)
		s.writeJSONRPCError(w, jsonrpc.CodeInternalError, "internal proxy error")
		return
	}

	// Copy relevant headers.
	copyHeaders(proxyReq.Header, r.Header)

	resp, err := s.httpClient.Do(proxyReq) //nolint:gosec // trusted config (see above)
	if err != nil {
		s.logger.Error("upstream request failed", "error", err)
		s.writeJSONRPCError(w, jsonrpc.CodeInternalError, "upstream server unavailable")
		return
	}
	defer resp.Body.Close()

	// Copy response headers.
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		s.logger.Error("failed to copy upstream response", "error", err)
	}
}

// handleSSE handles Server-Sent Events streaming by proxying the SSE connection
// to the upstream server and relaying events back to the client.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	upstreamURL := s.upstreamURL.JoinPath(r.URL.Path)
	upstreamURL.RawQuery = r.URL.RawQuery
	// upstream URL is derived from trusted server-side configuration (see forwardRequest comment).
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body) //nolint:gosec // trusted config
	if err != nil {
		s.logger.Error("failed to create SSE upstream request", "error", err)
		http.Error(w, "internal proxy error", http.StatusInternalServerError)
		return
	}

	copyHeaders(proxyReq.Header, r.Header)

	// Use the dedicated SSE HTTP client (Timeout=0) so long-lived streams
	// are not killed by the normal request timeout.
	resp, err := s.sseHTTPClient.Do(proxyReq) //nolint:gosec // trusted config
	if err != nil {
		s.logger.Error("SSE upstream request failed", "error", err)
		http.Error(w, "upstream server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	s.logger.Info("SSE connection established", "remote_addr", r.RemoteAddr)

	// Copy upstream response headers before setting SSE-specific overrides.
	// This forwards any custom headers from the upstream SSE server (e.g., session IDs)
	// while ensuring SSE protocol headers have the correct values.
	copyHeaders(w.Header(), resp.Header)

	// Override/set required SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(resp.StatusCode)

	// Stream events from upstream to client.
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				s.logger.Error("failed to write SSE event", "error", writeErr)
				return
			}
			flusher.Flush()
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				s.logger.Error("SSE upstream read error", "error", readErr)
			}
			return
		}
	}
}

// writeJSONRPCError writes a JSON-RPC 2.0 error response with a null ID.
// Per JSON-RPC 2.0 spec, ID is null when the request cannot be parsed.
func (s *Server) writeJSONRPCError(w http.ResponseWriter, code int, message string) {
	resp := jsonrpc.NewErrorResponse(nil, code, message)
	data, err := resp.Marshal()
	if err != nil {
		s.logger.Error("failed to marshal error response", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		s.logger.Error("failed to write error response", "error", err)
	}
}

// isSSERequest checks if the request is asking for an SSE stream.
func isSSERequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/event-stream")
}

// isMaxBytesError checks if the error is from exceeding MaxBytesReader limit.
func isMaxBytesError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

// copyHeaders copies HTTP headers, excluding hop-by-hop and
// security-sensitive headers that must not be forwarded.
// Used for both request headers (to upstream) and response headers (to client).
func copyHeaders(dst, src http.Header) {
	excluded := map[string]bool{
		// Hop-by-hop headers (RFC 2616 §13.5.1).
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
		// Security: the Authorization header carries the client's Bearer
		// token for gateway authentication. Forwarding it to upstream
		// would leak credentials to an external service.
		"Authorization": true,
		// Internal audit header: strip from both directions to prevent
		// leaking internal infrastructure details to clients or upstream.
		"X-Audit-Client-Id": true,
	}

	for key, values := range src {
		if excluded[key] {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
