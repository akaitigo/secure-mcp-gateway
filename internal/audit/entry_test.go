package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEntry(t *testing.T) {
	t.Parallel()

	metadata := map[string]string{"http_method": "POST"}
	entry := NewEntry("client-123", "tools/call", DecisionAllow, "req-456", metadata)

	assert.NotEmpty(t, entry.ID)
	assert.Equal(t, "client-123", entry.ClientID)
	assert.Equal(t, "tools/call", entry.ToolName)
	assert.Equal(t, DecisionAllow, entry.Decision)
	assert.Equal(t, "req-456", entry.RequestID)
	assert.Equal(t, "POST", entry.Metadata["http_method"])

	// Verify timestamp is valid RFC 3339.
	_, err := time.Parse(time.RFC3339, entry.Timestamp)
	require.NoError(t, err)
}

func TestNewEntry_DenyDecision(t *testing.T) {
	t.Parallel()

	entry := NewEntry("client-789", "tools/call", DecisionDeny, "req-000", nil)

	assert.Equal(t, DecisionDeny, entry.Decision)
	assert.Nil(t, entry.Metadata)
}

func TestNewEntry_UniqueIDs(t *testing.T) {
	t.Parallel()

	entry1 := NewEntry("c1", "tools/list", DecisionAllow, "r1", nil)
	entry2 := NewEntry("c2", "tools/list", DecisionAllow, "r2", nil)

	assert.NotEqual(t, entry1.ID, entry2.ID)
}

func TestGenerateID_Format(t *testing.T) {
	t.Parallel()

	id := generateID()
	// UUID v4 format: 8-4-4-4-12 hex characters.
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, id)
}
