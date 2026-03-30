package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akaitigo/secure-mcp-gateway/internal/config"
)

func TestLoad_Success(t *testing.T) {
	t.Setenv("UPSTREAM_MCP_URL", "http://localhost:3001")
	t.Setenv("PROXY_LISTEN_ADDR", ":9090")
	t.Setenv("HYDRA_ADMIN_URL", "http://localhost:4445")
	t.Setenv("AUDIT_LOG_PATH", "/var/log/audit.log")
	t.Setenv("GRPC_LISTEN_ADDR", ":50051")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "http://localhost:3001", cfg.UpstreamMCPURL)
	assert.Equal(t, ":9090", cfg.ProxyListenAddr)
	assert.Equal(t, "http://localhost:4445", cfg.HydraAdminURL)
	assert.Equal(t, "/var/log/audit.log", cfg.AuditLogPath)
	assert.Equal(t, ":50051", cfg.GRPCListenAddr)
}

func TestLoad_Defaults(t *testing.T) {
	t.Setenv("UPSTREAM_MCP_URL", "http://localhost:3001")
	t.Setenv("HYDRA_ADMIN_URL", "http://localhost:4445")
	// Clear optional env vars to test defaults.
	t.Setenv("PROXY_LISTEN_ADDR", "")
	t.Setenv("AUDIT_LOG_PATH", "")
	t.Setenv("GRPC_LISTEN_ADDR", "")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, ":8080", cfg.ProxyListenAddr)
	assert.Equal(t, "stdout", cfg.AuditLogPath)
	assert.Equal(t, ":9090", cfg.GRPCListenAddr)
}

func TestLoad_MissingUpstreamMCPURL(t *testing.T) {
	t.Setenv("UPSTREAM_MCP_URL", "")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UPSTREAM_MCP_URL is required")
}

func TestLoad_InvalidUpstreamMCPURL(t *testing.T) {
	t.Setenv("UPSTREAM_MCP_URL", "not-a-valid-url")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid URL")
}

func TestLoad_MissingHydraAdminURL(t *testing.T) {
	t.Setenv("UPSTREAM_MCP_URL", "http://localhost:3001")
	t.Setenv("HYDRA_ADMIN_URL", "")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HYDRA_ADMIN_URL is required")
}

func TestLoad_InvalidHydraAdminURL(t *testing.T) {
	t.Setenv("UPSTREAM_MCP_URL", "http://localhost:3001")
	t.Setenv("HYDRA_ADMIN_URL", "not-a-valid-url")

	_, err := config.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HYDRA_ADMIN_URL is not a valid URL")
}
