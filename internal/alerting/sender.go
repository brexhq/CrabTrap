package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Message represents a denial notification payload.
type Message struct {
	BotID   string
	Method  string
	Pattern string
	Reason  string
	URL     string // link to CrabTrap audit trail
}

// Sender delivers a notification message to a destination.
// Implementations are registered by channel_type (e.g., "slack").
// To add a new channel type, implement this interface and register it
// via Service.RegisterSender.
type Sender interface {
	Send(ctx context.Context, destination string, msg Message) error
}

// SlackSender posts messages to Slack using the Bot API (chat.postMessage).
type SlackSender struct {
	BotToken string
	client   *http.Client
}

func NewSlackSender(botToken string) *SlackSender {
	return &SlackSender{
		BotToken: botToken,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackSender) Send(ctx context.Context, destination string, msg Message) error {
	text := fmt.Sprintf("🚫 *Denial alert* for `%s`\n*%s %s*\nReason: %s",
		msg.BotID, msg.Method, msg.Pattern, msg.Reason)
	if msg.URL != "" {
		text += fmt.Sprintf("\n<%s|View in CrabTrap>", msg.URL)
	}

	payload := map[string]interface{}{
		"channel": destination,
		"text":    text,
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": text,
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://slack.com/api/chat.postMessage", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.BotToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("slack: decode response: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("slack: API error: %s", result.Error)
	}
	return nil
}

// WebhookSender posts notification payloads as JSON to the destination URL.
// Works with any webhook receiver (Slack incoming webhooks, Discord, webhook.site, etc.).
type WebhookSender struct {
	client *http.Client
}

func NewWebhookSender() *WebhookSender {
	return &WebhookSender{client: &http.Client{Timeout: 10 * time.Second}}
}

func (w *WebhookSender) Send(ctx context.Context, destination string, msg Message) error {
	payload := map[string]string{
		"text": fmt.Sprintf("Denial alert for %s: %s %s — %s", msg.BotID, msg.Method, msg.Pattern, msg.Reason),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, destination, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook: status %d", resp.StatusCode)
	}
	return nil
}
