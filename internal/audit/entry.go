// Package audit provides structured audit logging for MCP tool invocations.
// It records who called what tool, when, and whether the call was allowed or denied.
package audit

import (
	"crypto/rand"
	"fmt"
	"time"
)

// Decision represents the authorization outcome for a tool invocation.
type Decision string

const (
	// DecisionAllow indicates the tool invocation was permitted.
	DecisionAllow Decision = "ALLOW"
	// DecisionDeny indicates the tool invocation was rejected.
	DecisionDeny Decision = "DENY"
)

// Entry represents a single audit log record.
type Entry struct {
	// Metadata holds additional context (e.g., HTTP method, remote addr).
	Metadata map[string]string `json:"metadata,omitempty"`
	// ID is the unique identifier for this audit entry (UUID v4).
	ID string `json:"id"`
	// ClientID is the OAuth2 client that initiated the request.
	ClientID string `json:"client_id"`
	// ToolName is the MCP tool that was invoked (e.g., "tools/call").
	ToolName string `json:"tool_name"`
	// Decision is the authorization outcome ("ALLOW" or "DENY").
	Decision Decision `json:"decision"`
	// Timestamp is the time of the request in RFC 3339 format.
	Timestamp string `json:"timestamp"`
	// RequestID is the unique request correlation identifier.
	RequestID string `json:"request_id"`
}

// NewEntry creates a new audit entry with the given parameters.
// It automatically generates an ID and timestamp.
func NewEntry(clientID, toolName string, decision Decision, requestID string, metadata map[string]string) *Entry {
	return &Entry{
		ID:        generateID(),
		ClientID:  clientID,
		ToolName:  toolName,
		Decision:  decision,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: requestID,
		Metadata:  metadata,
	}
}

// generateID creates a UUID v4 string.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: should never happen in practice.
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	// Set version (4) and variant (RFC 4122).
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
