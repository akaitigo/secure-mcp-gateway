package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_Log(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	store := NewStore()
	logger := NewLoggerWithWriter(&buf, store)

	entry := NewEntry("client-123", "tools/call", DecisionAllow, "req-456", map[string]string{
		"http_method": "POST",
		"path":        "/",
	})
	logger.Log(entry)

	// Verify structured log output.
	var logOutput map[string]any
	err := json.Unmarshal(buf.Bytes(), &logOutput)
	require.NoError(t, err)

	assert.Equal(t, "audit_log", logOutput["msg"])
	assert.Equal(t, "client-123", logOutput["client_id"])
	assert.Equal(t, "tools/call", logOutput["tool_name"])
	assert.Equal(t, "ALLOW", logOutput["decision"])
	assert.Equal(t, "req-456", logOutput["request_id"])
	assert.Equal(t, "POST", logOutput["meta.http_method"])
	assert.Equal(t, "/", logOutput["meta.path"])
	assert.NotEmpty(t, logOutput["audit_id"])
	assert.NotEmpty(t, logOutput["timestamp"])

	// Verify entry was stored.
	assert.Equal(t, 1, store.Count())
}

func TestLogger_LogDeny(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	store := NewStore()
	logger := NewLoggerWithWriter(&buf, store)

	entry := NewEntry("unknown", "tools/call", DecisionDeny, "req-000", nil)
	logger.Log(entry)

	var logOutput map[string]any
	err := json.Unmarshal(buf.Bytes(), &logOutput)
	require.NoError(t, err)

	assert.Equal(t, "DENY", logOutput["decision"])
	assert.Equal(t, "unknown", logOutput["client_id"])
}

func TestLogger_Store(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	store := NewStore()
	logger := NewLoggerWithWriter(&buf, store)

	assert.Same(t, store, logger.Store())
}

func TestLogger_MultipleEntries(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	store := NewStore()
	logger := NewLoggerWithWriter(&buf, store)

	for i := 0; i < 5; i++ {
		logger.Log(NewEntry("c", "tools/call", DecisionAllow, "r", nil))
	}

	assert.Equal(t, 5, store.Count())

	// Verify log output contains 5 JSON lines.
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	assert.Len(t, lines, 5)
}

func TestLogger_NoSensitiveData(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	store := NewStore()
	logger := NewLoggerWithWriter(&buf, store)

	entry := NewEntry("client-123", "tools/call", DecisionAllow, "req-456", map[string]string{
		"http_method": "POST",
	})
	logger.Log(entry)

	output := buf.String()
	// Ensure no token or bearer string appears.
	assert.NotContains(t, output, "Bearer")
	assert.NotContains(t, output, "token")
	assert.NotContains(t, output, "password")
}

func TestNewLogger_Stdout(t *testing.T) {
	t.Parallel()

	store := NewStore()
	logger, err := NewLogger("stdout", store)
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestNewLogger_EmptyPath(t *testing.T) {
	t.Parallel()

	store := NewStore()
	logger, err := NewLogger("", store)
	require.NoError(t, err)
	assert.NotNil(t, logger)
}

func TestNewLogger_InvalidPath(t *testing.T) {
	t.Parallel()

	store := NewStore()
	_, err := NewLogger("/nonexistent/dir/audit.log", store)
	require.Error(t, err)
}

func TestNewLogger_FileClose(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/audit_test.log"
	store := NewStore()
	logger, err := NewLogger(path, store)
	require.NoError(t, err)

	logger.Log(NewEntry("c", "tools/call", DecisionAllow, "r", nil))

	require.NoError(t, logger.Close())
}

func TestNewLogger_StdoutClose(t *testing.T) {
	t.Parallel()

	store := NewStore()
	logger, err := NewLogger("stdout", store)
	require.NoError(t, err)

	require.NoError(t, logger.Close())
}
