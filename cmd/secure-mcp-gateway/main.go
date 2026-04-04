package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akaitigo/secure-mcp-gateway/internal/audit"
	"github.com/akaitigo/secure-mcp-gateway/internal/auth"
	"github.com/akaitigo/secure-mcp-gateway/internal/config"
	"github.com/akaitigo/secure-mcp-gateway/internal/grpcserver"
	"github.com/akaitigo/secure-mcp-gateway/internal/proxy"
)

func main() {
	slog.Info("secure-mcp-gateway starting")
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Set up audit logging.
	auditStore := audit.NewStore()
	auditLogger, err := audit.NewLogger(cfg.AuditLogPath, auditStore)
	if err != nil {
		return err
	}
	auditMiddleware := audit.NewMiddleware(auditLogger,
		audit.WithSkipPaths("/health"),
	)

	// Set up OAuth2 token verification middleware.
	introspector, err := auth.NewHydraIntrospector(cfg.HydraAdminURL, nil)
	if err != nil {
		return err
	}
	authMiddleware := auth.NewMiddleware(introspector,
		auth.WithSkipPaths("/health"),
	)

	// Build proxy with middleware chain:
	// RequestID -> Audit -> Auth -> Proxy handler
	// Audit wraps Auth so that both ALLOW and DENY decisions are logged,
	// ensuring 100% audit log coverage per PRD requirements.
	srv, err := proxy.New(cfg.ProxyListenAddr, cfg.UpstreamMCPURL,
		proxy.WithMiddleware(audit.RequestIDMiddleware),
		proxy.WithMiddleware(auditMiddleware.Handler),
		proxy.WithMiddleware(authMiddleware.Handler),
	)
	if err != nil {
		return err
	}

	// Start gRPC management server.
	grpcSrv := grpcserver.New(auditStore)
	var lc net.ListenConfig
	grpcLn, err := lc.Listen(context.Background(), "tcp", cfg.GRPCListenAddr)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)

	go func() {
		errCh <- srv.ListenAndServe()
	}()

	go func() {
		errCh <- grpcSrv.Serve(grpcLn)
	}()

	// Graceful shutdown: listen for SIGTERM/SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	var startupErr error
	select {
	case sig := <-quit:
		slog.Info("received shutdown signal", "signal", sig)
	case startupErr = <-errCh:
		slog.Error("server error, initiating shutdown", "error", startupErr)
	}

	// Give in-flight requests up to 30 seconds to complete.
	// GracefulStop is always called regardless of how shutdown was triggered.
	const shutdownTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	grpcSrv.GracefulStop()
	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	// Close audit log file if it was opened (no-op for stdout).
	if err := auditLogger.Close(); err != nil {
		slog.Error("failed to close audit log", "error", err)
	}
	return startupErr
}
