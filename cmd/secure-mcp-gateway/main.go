package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akaitigo/secure-mcp-gateway/internal/config"
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

	srv, err := proxy.New(cfg.ProxyListenAddr, cfg.UpstreamMCPURL)
	if err != nil {
		return err
	}

	// Graceful shutdown: listen for SIGTERM/SIGINT.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-quit:
		slog.Info("received shutdown signal", "signal", sig)
	case err := <-errCh:
		return err
	}

	// Give in-flight requests up to 30 seconds to complete.
	const shutdownTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return srv.Shutdown(ctx)
}
