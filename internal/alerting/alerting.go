package alerting

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// ManagerResolver resolves which managers oversee a given bot.
type ManagerResolver interface {
	ManagersForBot(ctx context.Context, botID string) ([]string, error)
}

// Summarizer generates a human-readable summary from a batch of denials.
type Summarizer interface {
	Summarize(ctx context.Context, botID string, denials []DenialInfo) (string, error)
}

// DenialInfo holds the details of a single denial.
type DenialInfo struct {
	ID     string
	Method string
	URL    string
	Reason string
}

// MetricsObserver receives alerting metrics events.
type MetricsObserver interface {
	RecordAlertDenialBuffered(ctx context.Context)
	RecordAlertNotificationSent(ctx context.Context, channelType string)
	RecordAlertFlushError(ctx context.Context, reason string)
}

// Service implements notifications.Channel and dispatches batched denial
// alerts. Denials are buffered in PostgreSQL for multi-replica safety.
// A background ticker periodically flushes buffered denials using a
// pg_advisory_lock to ensure only one replica sends at a time.
type Service struct {
	store      Store
	resolver   ManagerResolver
	summarizer Summarizer
	senders    map[string]Sender
	sendersMu  sync.RWMutex
	metrics    MetricsObserver
	batchWait  time.Duration
	inflight   sync.WaitGroup
	stopOnce   sync.Once
	stopCh     chan struct{}
}

func NewService(store Store, resolver ManagerResolver, summarizer Summarizer, batchWait time.Duration) *Service {
	s := &Service{
		store:      store,
		resolver:   resolver,
		summarizer: summarizer,
		senders:    make(map[string]Sender),
		batchWait:  batchWait,
		stopCh:     make(chan struct{}),
	}
	go s.flushLoop()
	return s
}

func (s *Service) RegisterSender(channelType string, sender Sender) {
	s.sendersMu.Lock()
	defer s.sendersMu.Unlock()
	s.senders[channelType] = sender
}

func (s *Service) SetMetrics(m MetricsObserver) {
	s.metrics = m
}

func (s *Service) SenderFor(channelType string) Sender {
	s.sendersMu.RLock()
	defer s.sendersMu.RUnlock()
	return s.senders[channelType]
}

func (s *Service) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.inflight.Wait()
}

// FlushNow triggers an immediate flush (used in tests).
func (s *Service) FlushNow() {
	s.tryFlush()
}

// Name implements notifications.Channel.
func (s *Service) Name() string { return "alerting" }

// Notify implements notifications.Channel. Buffers denied audit entries in PG.
func (s *Service) Notify(event notifications.Event) error {
	if event.Type != notifications.EventAuditEntry {
		return nil
	}
	entry, ok := event.Data.(*types.AuditEntry)
	if !ok || entry == nil {
		return nil
	}
	if entry.Decision != "denied" || entry.UserID == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.BufferDenial(ctx, entry.UserID, entry.Method, entry.URL, entry.LLMReason); err != nil {
		slog.Error("alerting: buffer denial", "error", err, "bot_id", entry.UserID)
	} else if s.metrics != nil {
		s.metrics.RecordAlertDenialBuffered(ctx)
	}
	return nil
}

// flushLoop periodically checks for buffered denials ready to send.
func (s *Service) flushLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.inflight.Add(1)
			s.tryFlush()
			s.inflight.Done()
		}
	}
}

func (s *Service) tryFlush() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	locked, unlock, err := s.store.TryAdvisoryLock(ctx)
	if err != nil {
		slog.Error("alerting: advisory lock", "error", err)
		return
	}
	if !locked {
		return
	}
	defer unlock()

	botDenials, err := s.store.FlushableDenials(ctx, s.batchWait)
	if err != nil {
		slog.Error("alerting: query flushable denials", "error", err)
		return
	}

	for botID, denials := range botDenials {
		s.flushBot(ctx, botID, denials)
	}
}

func (s *Service) flushBot(ctx context.Context, botID string, denials []DenialInfo) {
	managerIDs, err := s.resolver.ManagersForBot(ctx, botID)
	if err != nil {
		slog.Error("alerting: resolve managers", "error", err, "bot_id", botID)
		return
	}
	if len(managerIDs) == 0 {
		slog.Debug("alerting: no managers, deleting buffer", "bot_id", botID, "count", len(denials))
		s.deleteFlushed(ctx, denials)
		return
	}

	channels, err := s.store.ListActiveChannelsForBot(ctx, botID)
	if err != nil {
		slog.Error("alerting: list channels", "error", err, "bot_id", botID)
		return
	}
	if len(channels) == 0 {
		slog.Debug("alerting: no channels, deleting buffer", "bot_id", botID, "count", len(denials))
		s.deleteFlushed(ctx, denials)
		return
	}

	summary, err := s.summarizer.Summarize(ctx, botID, denials)
	if err != nil {
		slog.Error("alerting: summarize failed, sending without summary", "error", err, "bot_id", botID)
		if s.metrics != nil {
			s.metrics.RecordAlertFlushError(ctx, "summarize")
		}
		summary = fmt.Sprintf("%d requests were denied. LLM summary unavailable.", len(denials))
	}

	managerSet := make(map[string]bool, len(managerIDs))
	for _, id := range managerIDs {
		managerSet[id] = true
	}

	msg := Message{
		BotID:   botID,
		Denials: denials,
		Summary: summary,
	}

	for _, ch := range channels {
		if !managerSet[ch.OwnerID] {
			continue
		}
		sender := s.SenderFor(ch.ChannelType)
		if sender == nil {
			continue
		}
		if err := sender.Send(ctx, ch.Destination, msg); err != nil {
			slog.Error("alerting: send failed", "error", err, "channel_id", ch.ID)
			if s.metrics != nil {
				s.metrics.RecordAlertFlushError(ctx, "send")
			}
		} else if s.metrics != nil {
			s.metrics.RecordAlertNotificationSent(ctx, ch.ChannelType)
		}
	}

	// Always delete after flush — even on send failure. Retrying broken sender
	// config forever would fill the buffer. Errors are logged + metricked.
	s.deleteFlushed(ctx, denials)
}

func (s *Service) deleteFlushed(ctx context.Context, denials []DenialInfo) {
	ids := make([]string, len(denials))
	for i, d := range denials {
		ids[i] = d.ID
	}
	if err := s.store.DeleteBufferedDenials(ctx, ids); err != nil {
		slog.Error("alerting: delete flushed", "error", err)
	}
}
