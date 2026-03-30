// Package grpcserver implements the gRPC management API for secure-mcp-gateway.
package grpcserver

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gatewayv1 "github.com/akaitigo/secure-mcp-gateway/gen/gateway/v1"
	"github.com/akaitigo/secure-mcp-gateway/internal/audit"
)

// defaultPageSize is the default number of audit logs returned per page.
const defaultPageSize = 20

// maxPageSize is the maximum number of audit logs returned per page.
const maxPageSize = 100

// Server implements the GatewayService gRPC server.
type Server struct {
	gatewayv1.UnimplementedGatewayServiceServer
	auditStore *audit.Store
	logger     *slog.Logger
	grpcServer *grpc.Server
}

// Option configures the gRPC server.
type Option func(*Server)

// WithLogger sets a custom logger for the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

// New creates a new gRPC server for the gateway management API.
func New(auditStore *audit.Store, opts ...Option) *Server {
	s := &Server{
		auditStore: auditStore,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.grpcServer = grpc.NewServer()
	gatewayv1.RegisterGatewayServiceServer(s.grpcServer, s)
	return s
}

// Serve starts the gRPC server on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	s.logger.Info("gRPC server starting", "addr", ln.Addr().String())
	if err := s.grpcServer.Serve(ln); err != nil {
		return fmt.Errorf("gRPC server error: %w", err)
	}
	return nil
}

// GracefulStop gracefully stops the gRPC server.
func (s *Server) GracefulStop() {
	s.logger.Info("gRPC server shutting down")
	s.grpcServer.GracefulStop()
}

// Health implements the Health RPC.
func (s *Server) Health(_ context.Context, _ *gatewayv1.HealthRequest) (*gatewayv1.HealthResponse, error) {
	return &gatewayv1.HealthResponse{Status: "SERVING"}, nil
}

// ListAuditLogs implements the ListAuditLogs RPC.
// It returns a paginated list of audit log entries from the in-memory store.
func (s *Server) ListAuditLogs(_ context.Context, req *gatewayv1.ListAuditLogsRequest) (*gatewayv1.ListAuditLogsResponse, error) {
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	// Parse page_token as offset. Empty = start from beginning.
	offset := 0
	if token := req.GetPageToken(); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid page_token: %s", token)
		}
		if parsed < 0 {
			return nil, status.Error(codes.InvalidArgument, "page_token must be non-negative")
		}
		offset = parsed
	}

	entries, total := s.auditStore.List(offset, pageSize)

	// Build response.
	logs := make([]*gatewayv1.AuditLog, 0, len(entries))
	for _, e := range entries {
		logs = append(logs, &gatewayv1.AuditLog{
			Id:        e.ID,
			ClientId:  e.ClientID,
			ToolName:  e.ToolName,
			Decision:  string(e.Decision),
			Timestamp: e.Timestamp,
			Metadata:  e.Metadata,
		})
	}

	// Determine next page token.
	nextPageToken := ""
	nextOffset := offset + len(entries)
	if nextOffset < total {
		nextPageToken = strconv.Itoa(nextOffset)
	}

	// Safely convert total to int32, capping at max int32.
	totalCount := int32(min(total, math.MaxInt32)) //nolint:gosec // capped above

	return &gatewayv1.ListAuditLogsResponse{
		AuditLogs:     logs,
		NextPageToken: nextPageToken,
		TotalCount:    totalCount,
	}, nil
}
