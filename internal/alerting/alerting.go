package alerting

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

const defaultBatchWindow = 30 * time.Second

// ManagerResolver resolves which managers oversee a given bot.
type ManagerResolver interface {
	ManagersForBot(ctx context.Context, botID string) ([]string, error)
}

// Summarizer generates a human-readable summary of what a bot was trying to do.
// Receives all denied patterns from a batch window so it can infer multi-request operations.
type Summarizer interface {
	Summarize(ctx context.Context, botID string, denials []DenialInfo) (string, error)
}

// DenialInfo holds the details of a single denial within a batch.
type DenialInfo struct {
	Method  string
	Pattern string
	Reason  string
}

// Service implements notifications.Channel and dispatches denial alerts
// to managers' configured notification channels. Denials are batched per
// bot within a time window so the LLM summarizer can see multi-request
// operations as a group.
type Service struct {
	store      Store
	resolver   ManagerResolver
	senders    map[string]Sender
	summarizer Summarizer
	cooldown   time.Duration
	batchWait  time.Duration
	dedup      map[string]time.Time // "botID\x00pattern" → cooldown_until
	dedupMu    sync.RWMutex
	batches    map[string]*batch // botID → pending batch
	batchMu    sync.Mutex
	stopOnce   sync.Once
	stopCh     chan struct{}
}

type batch struct {
	denials []DenialInfo
	timer   *time.Timer
}

func NewService(store Store, resolver ManagerResolver, cooldown time.Duration) *Service {
	s := &Service{
		store:     store,
		resolver:  resolver,
		senders:   make(map[string]Sender),
		cooldown:  cooldown,
		batchWait: defaultBatchWindow,
		dedup:     make(map[string]time.Time),
		batches:   make(map[string]*batch),
		stopCh:    make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *Service) RegisterSender(channelType string, sender Sender) {
	s.senders[channelType] = sender
}

func (s *Service) SetSummarizer(sum Summarizer) {
	s.summarizer = sum
}

func (s *Service) SetBatchWindow(d time.Duration) {
	s.batchWait = d
}

func (s *Service) SenderFor(channelType string) Sender {
	return s.senders[channelType]
}

func (s *Service) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.batchMu.Lock()
		var wg sync.WaitGroup
		for botID, b := range s.batches {
			b.timer.Stop()
			wg.Add(1)
			go func(id string, denials []DenialInfo) {
				defer wg.Done()
				s.flushBatch(id, denials)
			}(botID, b.denials)
		}
		s.batches = make(map[string]*batch)
		s.batchMu.Unlock()
		wg.Wait()
	})
}

// Name implements notifications.Channel.
func (s *Service) Name() string { return "alerting" }

// Notify implements notifications.Channel. Called by the dispatcher for every event.
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

	pattern := normalizePattern(entry.URL, entry.RequestBody)
	key := entry.UserID + "\x00" + pattern

	if s.inCooldown(key) {
		return nil
	}

	// Set cooldown immediately to prevent duplicates.
	s.setCooldown(key, time.Now().Add(s.cooldown))

	s.addToBatch(entry.UserID, DenialInfo{
		Method:  entry.Method,
		Pattern: pattern,
		Reason:  entry.LLMReason,
	})
	return nil
}

func (s *Service) addToBatch(botID string, info DenialInfo) {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	b, exists := s.batches[botID]
	if !exists {
		b = &batch{}
		b.timer = time.AfterFunc(s.batchWait, func() {
			s.batchMu.Lock()
			pending := s.batches[botID]
			delete(s.batches, botID)
			s.batchMu.Unlock()
			if pending != nil {
				go s.flushBatch(botID, pending.denials)
			}
		})
		s.batches[botID] = b
	} else {
		b.timer.Reset(s.batchWait)
	}
	b.denials = append(b.denials, info)
}

func (s *Service) flushBatch(botID string, denials []DenialInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Record each pattern in DB for multi-instance dedup.
	for _, d := range denials {
		cooldownUntil := time.Now().Add(s.cooldown)
		if err := s.store.RecordNotification(ctx, botID, d.Pattern, cooldownUntil); err != nil {
			slog.Error("alerting: record notification", "error", err, "bot_id", botID, "pattern", d.Pattern)
		}
	}

	managerIDs, err := s.resolver.ManagersForBot(ctx, botID)
	if err != nil {
		slog.Error("alerting: resolve managers", "error", err, "bot_id", botID)
		return
	}

	channels, err := s.store.ListChannelsForBot(ctx, botID)
	if err != nil {
		slog.Error("alerting: list channels", "error", err, "bot_id", botID)
		return
	}

	managerSet := make(map[string]bool, len(managerIDs))
	for _, id := range managerIDs {
		managerSet[id] = true
	}

	var summary string
	if s.summarizer != nil {
		sumCtx, sumCancel := context.WithTimeout(ctx, 10*time.Second)
		summary, _ = s.summarizer.Summarize(sumCtx, botID, denials)
		sumCancel()
	}

	msg := Message{
		BotID:   botID,
		Denials: denials,
		Summary: summary,
	}
	// For backward compat with single-denial messages
	if len(denials) == 1 {
		msg.Method = denials[0].Method
		msg.Pattern = denials[0].Pattern
		msg.Reason = denials[0].Reason
	}

	for _, ch := range channels {
		if !managerSet[ch.OwnerID] {
			continue
		}
		sender, ok := s.senders[ch.ChannelType]
		if !ok {
			slog.Warn("alerting: no sender for channel type", "channel_type", ch.ChannelType)
			continue
		}
		if err := sender.Send(ctx, ch.Destination, msg); err != nil {
			slog.Error("alerting: send failed", "error", err, "channel_id", ch.ID, "destination", ch.Destination)
		}
	}
}

func (s *Service) inCooldown(key string) bool {
	s.dedupMu.RLock()
	defer s.dedupMu.RUnlock()
	until, ok := s.dedup[key]
	return ok && time.Now().Before(until)
}

func (s *Service) setCooldown(key string, until time.Time) {
	s.dedupMu.Lock()
	defer s.dedupMu.Unlock()
	s.dedup[key] = until
}

func (s *Service) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.dedupMu.Lock()
			now := time.Now()
			for k, until := range s.dedup {
				if now.After(until) {
					delete(s.dedup, k)
				}
			}
			s.dedupMu.Unlock()
		}
	}
}
