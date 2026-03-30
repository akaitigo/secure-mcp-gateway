// Package config provides configuration loading from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
)

// Config holds the application configuration loaded from environment variables.
type Config struct {
	// UpstreamMCPURL is the URL of the upstream MCP server to proxy requests to.
	UpstreamMCPURL string
	// ProxyListenAddr is the address for the HTTP proxy to listen on.
	ProxyListenAddr string
	// HydraAdminURL is the ORY Hydra Admin API URL for token introspection.
	HydraAdminURL string
	// OPAURL is the OPA server URL for policy evaluation.
	OPAURL string
	// AuditLogPath is the output path for audit logs ("stdout" or a file path).
	AuditLogPath string
	// GRPCListenAddr is the address for the gRPC management API to listen on.
	GRPCListenAddr string
}

// Load reads configuration from environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		UpstreamMCPURL:  os.Getenv("UPSTREAM_MCP_URL"),
		ProxyListenAddr: envOrDefault("PROXY_LISTEN_ADDR", ":8080"),
		HydraAdminURL:   os.Getenv("HYDRA_ADMIN_URL"),
		OPAURL:          os.Getenv("OPA_URL"),
		AuditLogPath:    envOrDefault("AUDIT_LOG_PATH", "stdout"),
		GRPCListenAddr:  envOrDefault("GRPC_LISTEN_ADDR", ":9090"),
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.UpstreamMCPURL == "" {
		return errors.New("UPSTREAM_MCP_URL is required")
	}

	if _, err := url.ParseRequestURI(c.UpstreamMCPURL); err != nil {
		return fmt.Errorf("UPSTREAM_MCP_URL is not a valid URL: %w", err)
	}

	if c.HydraAdminURL == "" {
		return errors.New("HYDRA_ADMIN_URL is required")
	}

	if _, err := url.ParseRequestURI(c.HydraAdminURL); err != nil {
		return fmt.Errorf("HYDRA_ADMIN_URL is not a valid URL: %w", err)
	}

	return nil
}

func envOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
