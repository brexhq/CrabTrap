package alerting

import (
	"context"
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

// Service implements notifications.Channel and dispatches denial alerts
// to managers' configured notification channels.
type Service struct {
	store     Store
	resolver  ManagerResolver
	senders   map[string]Sender
	cooldown  time.Duration
	dedup     map[string]time.Time // "botID\x00pattern" → cooldown_until
	dedupMu   sync.RWMutex
	stopOnce  sync.Once
	stopCh    chan struct{}
}

func NewService(store Store, resolver ManagerResolver, cooldown time.Duration) *Service {
	s := &Service{
		store:    store,
		resolver: resolver,
		senders:  make(map[string]Sender),
		cooldown: cooldown,
		dedup:    make(map[string]time.Time),
		stopCh:   make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *Service) RegisterSender(channelType string, sender Sender) {
	s.senders[channelType] = sender
}

func (s *Service) SenderFor(channelType string) Sender {
	return s.senders[channelType]
}

func (s *Service) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
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

	// Set cooldown immediately to prevent duplicate goroutines for the same pattern.
	s.setCooldown(key, time.Now().Add(s.cooldown))

	go s.dispatch(entry.UserID, pattern, key, entry.Method, entry.LLMReason)
	return nil
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

func (s *Service) dispatch(botID, pattern, key, method, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	inCooldown, err := s.store.CheckCooldown(ctx, botID, pattern)
	if err != nil {
		slog.Error("alerting: check cooldown", "error", err, "bot_id", botID, "pattern", pattern)
		return
	}
	if inCooldown {
		s.setCooldown(key, time.Now().Add(s.cooldown))
		return
	}

	cooldownUntil := time.Now().Add(s.cooldown)
	if err := s.store.RecordNotification(ctx, botID, pattern, cooldownUntil); err != nil {
		slog.Error("alerting: record notification", "error", err, "bot_id", botID, "pattern", pattern)
		return
	}
	s.setCooldown(key, cooldownUntil)

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

	msg := Message{
		BotID:   botID,
		Method:  method,
		Pattern: pattern,
		Reason:  reason,
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
