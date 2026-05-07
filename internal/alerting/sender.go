package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Message represents a batched denial notification.
type Message struct {
	BotID   string
	Denials []DenialInfo
	Summary string // LLM-generated summary
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
	botToken string
	client   *http.Client
}

func NewSlackSender(botToken string) *SlackSender {
	return &SlackSender{
		botToken: botToken,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackSender) Send(ctx context.Context, destination string, msg Message) error {
	text := fmt.Sprintf(":rotating_light: *Denial summary* for `%s` (%d blocked requests)\n\n%s",
		slackEscape(msg.BotID), len(msg.Denials), slackEscape(msg.Summary))

	// Group repeated URLs with counts
	urlCounts := make(map[string]int)
	var urlOrder []string
	for _, d := range msg.Denials {
		key := d.Method + " " + d.URL
		if urlCounts[key] == 0 {
			urlOrder = append(urlOrder, key)
		}
		urlCounts[key]++
	}

	text += "\n\nRequests blocked:"
	for _, key := range urlOrder {
		count := urlCounts[key]
		if count > 1 {
			text += fmt.Sprintf("\n• `%s` (%dx)", slackEscape(key), count)
		} else {
			text += fmt.Sprintf("\n• `%s`", slackEscape(key))
		}
	}

	payload := map[string]interface{}{
		"channel": destination,
		"text":    text,
	}
	// Only use blocks if under Slack's 3000-char limit for section text.
	if len(text) <= 3000 {
		payload["blocks"] = []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": text,
				},
			},
		}
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
	req.Header.Set("Authorization", "Bearer "+s.botToken)

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

func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
