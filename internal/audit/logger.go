package audit

import (
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
		dispatcher.Broadcast(notifications.Event{
			Type: notifications.EventAuditEntry,
			Data: &entry,
		})
	}

	// Strip sensitive request/response payload data from file/stderr
	// output. Full data remains in the database for authenticated
	// admin access via the web UI.
	attrs := []any{
		"timestamp", entry.Timestamp,
		"request_id", entry.RequestID,
		"user_id", entry.UserID,
		"method", entry.Method,
		"url", entry.URL,
		"operation", entry.Operation,
		"decision", entry.Decision,
		"cache_hit", entry.CacheHit,
		"approved_by", entry.ApprovedBy,
		"approved_at", entry.ApprovedAt,
		"channel", entry.Channel,
		"response_status", entry.ResponseStatus,
		"duration_ms", entry.DurationMs,
		"error", entry.Error,
		"llm_response_id", entry.LLMResponseID,
		"llm_policy_id", entry.LLMPolicyID,
	}
	if len(entry.ProbeScores) > 0 || entry.ProbeTripped != "" || entry.ProbeCircuitOpen {
		attrs = append(attrs,
			"probe_scores", entry.ProbeScores,
			"probe_tripped", entry.ProbeTripped,
			"probe_aggregation", entry.ProbeAggregation,
			"probe_circuit_open", entry.ProbeCircuitOpen,
		)
	}
	l.slogger.Info("audit", attrs...)

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
