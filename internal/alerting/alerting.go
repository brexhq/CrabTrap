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

// Summarizer generates a periodic digest of what a bot was trying to do.
type Summarizer interface {
	Summarize(ctx context.Context, botID string, denials []DenialInfo) (string, error)
}

// DenialInfo holds the details of a single denial.
type DenialInfo struct {
	Method  string
	Pattern string
	Reason  string
}

// Service implements notifications.Channel and dispatches denial alerts
// to managers' configured notification channels. Each new denied pattern
// triggers an immediate notification. A separate periodic digest summarizes
// all denials using an LLM.
type Service struct {
	store      Store
	resolver   ManagerResolver
	senders    map[string]Sender
	summarizer Summarizer
	cooldown   time.Duration
	digestInterval time.Duration
	dedup      map[string]time.Time // "botID\x00pattern" → cooldown_until
	dedupMu    sync.RWMutex
	stopOnce   sync.Once
	stopCh     chan struct{}
}

func NewService(store Store, resolver ManagerResolver, cooldown time.Duration) *Service {
	s := &Service{
		store:          store,
		resolver:       resolver,
		senders:        make(map[string]Sender),
		cooldown:       cooldown,
		digestInterval: time.Hour,
		dedup:          make(map[string]time.Time),
		stopCh:         make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *Service) RegisterSender(channelType string, sender Sender) {
	s.senders[channelType] = sender
}

func (s *Service) SetSummarizer(sum Summarizer) {
	s.summarizer = sum
	if sum != nil {
		go s.digestLoop()
	}
}

func (s *Service) SetDigestInterval(d time.Duration) {
	s.digestInterval = d
}

func (s *Service) DigestIntervalValue() time.Duration {
	return s.digestInterval
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
// Sends an immediate notification for each new denied pattern.
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

	go s.dispatch(entry.UserID, pattern, key, entry.Method, entry.LLMReason)
	return nil
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

// digestLoop runs periodically to send LLM-summarized digests of recent denials.
func (s *Service) digestLoop() {
	ticker := time.NewTicker(s.digestInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.sendDigests()
		}
	}
}

func (s *Service) sendDigests() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	since := time.Now().Add(-s.digestInterval)
	botDenials, err := s.store.ListRecentDenials(ctx, since)
	if err != nil {
		slog.Error("alerting: list recent denials for digest", "error", err)
		return
	}

	for botID, denials := range botDenials {
		if len(denials) == 0 {
			continue
		}

		summary, err := s.summarizer.Summarize(ctx, botID, denials)
		if err != nil || summary == "" {
			continue
		}

		managerIDs, err := s.resolver.ManagersForBot(ctx, botID)
		if err != nil {
			continue
		}

		channels, err := s.store.ListChannelsForBot(ctx, botID)
		if err != nil {
			continue
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
			sender, ok := s.senders[ch.ChannelType]
			if !ok {
				continue
			}
			if err := sender.Send(ctx, ch.Destination, msg); err != nil {
				slog.Error("alerting: digest send failed", "error", err, "channel_id", ch.ID)
			}
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
