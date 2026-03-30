package audit

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Logger is a specialized audit logger that writes structured JSON logs
// and stores entries in the in-memory store for gRPC retrieval.
type Logger struct {
	slogger *slog.Logger
	store   *Store
}

// NewLogger creates a new audit logger.
// logPath controls the output destination: "stdout" writes to os.Stdout,
// any other value is treated as a file path.
func NewLogger(logPath string, store *Store) (*Logger, error) {
	var w io.Writer

	switch logPath {
	case "stdout", "":
		w = os.Stdout
	default:
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		w = f
	}

	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})

	return &Logger{
		slogger: slog.New(handler),
		store:   store,
	}, nil
}

// NewLoggerWithWriter creates an audit logger that writes to the given writer.
// Useful for testing.
func NewLoggerWithWriter(w io.Writer, store *Store) *Logger {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	return &Logger{
		slogger: slog.New(handler),
		store:   store,
	}
}

// Log writes an audit entry to both the structured logger and the in-memory store.
// Sensitive information (tokens, request bodies) is never included.
func (l *Logger) Log(entry *Entry) {
	attrs := []slog.Attr{
		slog.String("audit_id", entry.ID),
		slog.String("client_id", entry.ClientID),
		slog.String("tool_name", entry.ToolName),
		slog.String("decision", string(entry.Decision)),
		slog.String("request_id", entry.RequestID),
		slog.String("timestamp", entry.Timestamp),
	}

	for k, v := range entry.Metadata {
		attrs = append(attrs, slog.String("meta."+k, v))
	}

	// Use LogAttrs for structured output without extra allocations.
	l.slogger.LogAttrs(context.Background(), slog.LevelInfo, "audit_log", attrs...)

	l.store.Append(entry)
}

// Store returns the underlying audit store.
func (l *Logger) Store() *Store {
	return l.store
}
