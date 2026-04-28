package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// Logger writes audit entries as structured JSON via slog to stderr or a file.
type Logger struct {
	slogger    *slog.Logger
	file       *os.File // non-nil when writing to a file (for Close/Sync)
	console    bool
	mu         sync.Mutex
	dispatcher *notifications.Dispatcher
}

// NewLogger creates a new audit logger. Output may be "stderr" (default),
// "stdout", or a file path.
func NewLogger(output string) (*Logger, error) {
	var writer *os.File
	switch output {
	case "stdout":
		writer = os.Stdout
	case "stderr", "":
		writer = os.Stderr
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log file: %w", err)
		}
		writer = f
	}
	l := &Logger{
		slogger: slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{})),
		console: writer == os.Stdout || writer == os.Stderr,
	}
	if writer != os.Stdout && writer != os.Stderr {
		l.file = writer
	}
	return l, nil
}

// SetDispatcher wires up the notification dispatcher for real-time SSE audit events.
func (l *Logger) SetDispatcher(dispatcher *notifications.Dispatcher) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dispatcher = dispatcher
}

// LogRequest writes an audit entry via slog and broadcasts via SSE.
func (l *Logger) LogRequest(entry types.AuditEntry) {
	l.mu.Lock()
	dispatcher := l.dispatcher
	l.mu.Unlock()

	if dispatcher != nil {
		eventEntry := entry
		eventEntry.RequestBody = ""
		eventEntry.ResponseBody = ""
		eventEntry.RequestHeaders = nil
		eventEntry.ResponseHeaders = nil
		dispatcher.Broadcast(notifications.Event{
			Type: notifications.EventAuditEntry,
			Data: &eventEntry,
		})
	}

	logEntry := entry
	if l.shouldStripBodiesInStructuredOutput() {
		logEntry.RequestBody = ""
		logEntry.ResponseBody = ""
	}

	l.slogger.Info("audit",
		"timestamp", logEntry.Timestamp,
		"request_id", logEntry.RequestID,
		"user_id", logEntry.UserID,
		"method", logEntry.Method,
		"url", logEntry.URL,
		"operation", logEntry.Operation,
		"decision", logEntry.Decision,
		"cache_hit", logEntry.CacheHit,
		"approved_by", logEntry.ApprovedBy,
		"approved_at", logEntry.ApprovedAt,
		"channel", logEntry.Channel,
		"response_status", logEntry.ResponseStatus,
		"duration_ms", logEntry.DurationMs,
		"error", logEntry.Error,
		"request_body", logEntry.RequestBody,
		"response_body", logEntry.ResponseBody,
		"llm_response_id", logEntry.LLMResponseID,
		"llm_policy_id", logEntry.LLMPolicyID,
	)

	if l.file != nil {
		l.file.Sync()
	}
}

// Close closes the audit logger.
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) shouldStripBodiesInStructuredOutput() bool {
	return l.console && !slog.Default().Enabled(context.Background(), slog.LevelDebug)
}
