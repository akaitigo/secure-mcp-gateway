package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.Info("secure-mcp-gateway starting")
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// Proxy server implementation will be added in Issue #2.
	return nil
}
