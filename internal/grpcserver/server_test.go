package grpcserver

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gatewayv1 "github.com/akaitigo/secure-mcp-gateway/gen/gateway/v1"
	"github.com/akaitigo/secure-mcp-gateway/internal/audit"
)

// newTestServer creates a gRPC server and client for testing.
// Returns the client and a cleanup function.
func newTestServer(t *testing.T, store *audit.Store) (gatewayv1.GatewayServiceClient, func()) {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv := New(store, WithLogger(logger))

	ln, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	go func() {
		_ = srv.Serve(ln)
	}()

	conn, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := gatewayv1.NewGatewayServiceClient(conn)

	cleanup := func() {
		conn.Close()
		srv.GracefulStop()
	}

	return client, cleanup
}

func TestHealth(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	client, cleanup := newTestServer(t, store)
	defer cleanup()

	resp, err := client.Health(t.Context(), &gatewayv1.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, "SERVING", resp.Status)
}

func TestListAuditLogs_Empty(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	client, cleanup := newTestServer(t, store)
	defer cleanup()

	resp, err := client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.AuditLogs)
	assert.Equal(t, int32(0), resp.TotalCount)
	assert.Empty(t, resp.NextPageToken)
}

func TestListAuditLogs_WithEntries(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	for i := 0; i < 3; i++ {
		store.Append(audit.NewEntry(
			fmt.Sprintf("client-%d", i),
			"tools/call",
			audit.DecisionAllow,
			fmt.Sprintf("req-%d", i),
			map[string]string{"index": fmt.Sprintf("%d", i)},
		))
	}

	client, cleanup := newTestServer(t, store)
	defer cleanup()

	resp, err := client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{
		PageSize: 10,
	})
	require.NoError(t, err)

	assert.Len(t, resp.AuditLogs, 3)
	assert.Equal(t, int32(3), resp.TotalCount)
	assert.Empty(t, resp.NextPageToken)

	// Newest first.
	assert.Equal(t, "client-2", resp.AuditLogs[0].ClientId)
	assert.Equal(t, "client-1", resp.AuditLogs[1].ClientId)
	assert.Equal(t, "client-0", resp.AuditLogs[2].ClientId)
	assert.Equal(t, "ALLOW", resp.AuditLogs[0].Decision)
	assert.Equal(t, "tools/call", resp.AuditLogs[0].ToolName)
	assert.NotEmpty(t, resp.AuditLogs[0].Id)
	assert.NotEmpty(t, resp.AuditLogs[0].Timestamp)
	assert.Equal(t, "2", resp.AuditLogs[0].Metadata["index"])
}

func TestListAuditLogs_Pagination(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	for i := 0; i < 5; i++ {
		store.Append(audit.NewEntry(
			fmt.Sprintf("client-%d", i),
			"tools/call",
			audit.DecisionAllow,
			fmt.Sprintf("req-%d", i),
			nil,
		))
	}

	client, cleanup := newTestServer(t, store)
	defer cleanup()

	// Page 1.
	resp, err := client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{
		PageSize: 2,
	})
	require.NoError(t, err)
	assert.Len(t, resp.AuditLogs, 2)
	assert.Equal(t, int32(5), resp.TotalCount)
	assert.NotEmpty(t, resp.NextPageToken)

	// Page 2.
	resp, err = client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{
		PageSize:  2,
		PageToken: resp.NextPageToken,
	})
	require.NoError(t, err)
	assert.Len(t, resp.AuditLogs, 2)
	assert.NotEmpty(t, resp.NextPageToken)

	// Page 3 (last page).
	resp, err = client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{
		PageSize:  2,
		PageToken: resp.NextPageToken,
	})
	require.NoError(t, err)
	assert.Len(t, resp.AuditLogs, 1)
	assert.Empty(t, resp.NextPageToken)
}

func TestListAuditLogs_DefaultPageSize(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	for i := 0; i < 25; i++ {
		store.Append(audit.NewEntry("c", "tools/call", audit.DecisionAllow, "r", nil))
	}

	client, cleanup := newTestServer(t, store)
	defer cleanup()

	resp, err := client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.AuditLogs, 20) // Default page size.
	assert.NotEmpty(t, resp.NextPageToken)
}

func TestListAuditLogs_MaxPageSize(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	for i := 0; i < 150; i++ {
		store.Append(audit.NewEntry("c", "tools/call", audit.DecisionAllow, "r", nil))
	}

	client, cleanup := newTestServer(t, store)
	defer cleanup()

	resp, err := client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{
		PageSize: 200,
	})
	require.NoError(t, err)
	assert.Len(t, resp.AuditLogs, 100) // Capped to max.
}

func TestListAuditLogs_InvalidPageToken(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	client, cleanup := newTestServer(t, store)
	defer cleanup()

	_, err := client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{
		PageToken: "not-a-number",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid page_token")
}

func TestListAuditLogs_NegativePageToken(t *testing.T) {
	t.Parallel()

	store := audit.NewStore()
	client, cleanup := newTestServer(t, store)
	defer cleanup()

	_, err := client.ListAuditLogs(t.Context(), &gatewayv1.ListAuditLogsRequest{
		PageToken: "-1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-negative")
}
