package audit

import (
	"net/http"
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
	logger, err := NewLogger(t.TempDir() + "/audit.jsonl")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	dispatcher := notifications.NewDispatcher()
	channel := &captureChannel{}
	dispatcher.RegisterChannel(channel)
	logger.SetDispatcher(dispatcher)

	entry := types.AuditEntry{
		Timestamp:      time.Now(),
		RequestID:      "req_large_payload",
		Method:         "GET",
		URL:            "https://api.example.test/v1/items",
		Operation:      "READ",
		Decision:       "approved",
		ResponseStatus: http.StatusOK,
		RequestBody:    "large request body",
		ResponseBody:   "large response body",
	}

	logger.LogRequest(entry)

	got := channel.eventData(t)
	if got.RequestBody != "" {
		t.Fatalf("broadcast request body = %q, want empty", got.RequestBody)
	}
	if got.ResponseBody != "" {
		t.Fatalf("broadcast response body = %q, want empty", got.ResponseBody)
	}
	if got.RequestID != entry.RequestID {
		t.Fatalf("broadcast request ID = %q, want %q", got.RequestID, entry.RequestID)
	}

	if entry.RequestBody == "" || entry.ResponseBody == "" {
		t.Fatal("LogRequest mutated the caller's audit entry bodies")
	}
}
