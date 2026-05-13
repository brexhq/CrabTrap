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
// A background ticker periodically flushes buffered denials using an
// atomic DELETE ... FOR UPDATE to ensure each denial is processed exactly once.
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

	botDenials, err := s.store.ClaimFlushableDenials(ctx, s.batchWait)
	if err != nil {
		slog.Error("alerting: claim flushable denials", "error", err)
		return
	}

	for botID, denials := range botDenials {
		s.flushBot(ctx, botID, denials)
	}
}

func (s *Service) flushBot(ctx context.Context, botID string, denials []DenialInfo) {
	channels, err := s.store.ListActiveChannelsForBot(ctx, botID)
	if err != nil {
		slog.Error("alerting: list channels", "error", err, "bot_id", botID)
		return
	}
	if len(channels) == 0 {
		slog.Warn("alerting: no channels configured for bot, denials dropped", "bot_id", botID, "count", len(denials))
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

	msg := Message{
		BotID:   botID,
		Denials: denials,
		Summary: summary,
	}

	for _, ch := range channels {
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
}
