package audit

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

type captureChannel struct {
	mu    sync.Mutex
	event notifications.Event
}

func (c *captureChannel) Name() string {
	return "capture"
}

func (c *captureChannel) Notify(event notifications.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.event = event
	return nil
}

func (c *captureChannel) eventData(t *testing.T) *types.AuditEntry {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.event.Data.(*types.AuditEntry)
	if !ok {
		t.Fatalf("event data type = %T, want *types.AuditEntry", c.event.Data)
	}
	return entry
}

func TestLogRequestBroadcastsAuditEntryWithoutBodies(t *testing.T) {
	logger, err := NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	dispatcher := notifications.NewDispatcher()
	channel := &captureChannel{}
	dispatcher.RegisterChannel(channel)
	logger.SetDispatcher(dispatcher)

	entry := sampleAuditEntry()
	logger.LogRequest(entry)

	got := channel.eventData(t)
	if got.RequestBody != "" {
		t.Fatalf("broadcast request body = %q, want empty", got.RequestBody)
	}
	if got.ResponseBody != "" {
		t.Fatalf("broadcast response body = %q, want empty", got.ResponseBody)
	}
	if len(got.RequestHeaders) != 0 {
		t.Fatalf("broadcast request headers = %v, want empty", got.RequestHeaders)
	}
	if len(got.ResponseHeaders) != 0 {
		t.Fatalf("broadcast response headers = %v, want empty", got.ResponseHeaders)
	}
	if got.RequestID != entry.RequestID {
		t.Fatalf("broadcast request ID = %q, want %q", got.RequestID, entry.RequestID)
	}
	if entry.RequestBody == "" || entry.ResponseBody == "" {
		t.Fatal("LogRequest mutated the caller's audit entry bodies")
	}
	if len(entry.RequestHeaders) == 0 || len(entry.ResponseHeaders) == 0 {
		t.Fatal("LogRequest mutated the caller's audit entry headers")
	}
}

func TestLogRequestWritesBodiesToFileOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	entry := sampleAuditEntry()
	logger.LogRequest(entry)

	record := readStructuredAuditRecord(t, path)
	if got := recordString(t, record, "request_body"); got != entry.RequestBody {
		t.Fatalf("request_body = %q, want %q", got, entry.RequestBody)
	}
	if got := recordString(t, record, "response_body"); got != entry.ResponseBody {
		t.Fatalf("response_body = %q, want %q", got, entry.ResponseBody)
	}
}

func TestLogRequestStripsBodiesOnStdoutWhenDebugDisabled(t *testing.T) {
	output := captureStdoutAuditLog(t, false, sampleAuditEntry())
	record := decodeStructuredAuditRecord(t, output)

	if got := recordString(t, record, "request_body"); got != "" {
		t.Fatalf("request_body = %q, want empty", got)
	}
	if got := recordString(t, record, "response_body"); got != "" {
		t.Fatalf("response_body = %q, want empty", got)
	}
}

func TestLogRequestKeepsBodiesOnStdoutWhenDebugEnabled(t *testing.T) {
	entry := sampleAuditEntry()
	output := captureStdoutAuditLog(t, true, entry)
	record := decodeStructuredAuditRecord(t, output)

	if got := recordString(t, record, "request_body"); got != entry.RequestBody {
		t.Fatalf("request_body = %q, want %q", got, entry.RequestBody)
	}
	if got := recordString(t, record, "response_body"); got != entry.ResponseBody {
		t.Fatalf("response_body = %q, want %q", got, entry.ResponseBody)
	}
}

func sampleAuditEntry() types.AuditEntry {
	return types.AuditEntry{
		Timestamp:      time.Unix(1710000000, 0).UTC(),
		RequestID:      "req_large_payload",
		Method:         http.MethodGet,
		URL:            "https://api.example.test/v1/items",
		Operation:      "READ",
		Decision:       "approved",
		ResponseStatus: http.StatusOK,
		RequestHeaders: http.Header{
			"Authorization": []string{"Bearer secret-token"},
			"Cookie":        []string{"session=secret"},
		},
		RequestBody: "large request body",
		ResponseHeaders: http.Header{
			"Set-Cookie": []string{"session=secret"},
		},
		ResponseBody: "large response body",
	}
}

func readStructuredAuditRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return decodeStructuredAuditRecord(t, data)
}

func decodeStructuredAuditRecord(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return record
}

func recordString(t *testing.T, record map[string]any, key string) string {
	t.Helper()
	value, ok := record[key]
	if !ok || value == nil {
		return ""
	}
	s, ok := value.(string)
	if !ok {
		t.Fatalf("%s type = %T, want string", key, value)
	}
	return s
}

func captureStdoutAuditLog(t *testing.T, debug bool, entry types.AuditEntry) []byte {
	t.Helper()

	restoreDefault := captureDefaultLogger(t, debug)
	defer restoreDefault()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	logger, err := NewLogger("stdout")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	logger.LogRequest(entry)
	writer.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return data
}

func captureDefaultLogger(t *testing.T, debug bool) func() {
	t.Helper()

	old := slog.Default()
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: level})))
	return func() {
		slog.SetDefault(old)
	}
}
