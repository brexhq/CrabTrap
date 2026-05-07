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

// Message represents a denial notification payload.
type Message struct {
	BotID   string
	Method  string       // set for single-denial messages
	Pattern string       // set for single-denial messages
	Reason  string       // set for single-denial messages
	Denials []DenialInfo // all denied patterns in this batch
	Summary string       // LLM-generated summary (may be empty)
	URL     string       // link to CrabTrap audit trail
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
	var text string
	if len(msg.Denials) <= 1 {
		text = fmt.Sprintf(":no_entry: *Denial alert* for `%s`\n*%s %s*",
			slackEscape(msg.BotID), slackEscape(msg.Method), slackEscape(msg.Pattern))
	} else {
		text = fmt.Sprintf(":no_entry: *Denial alert* for `%s` (%d blocked requests)",
			slackEscape(msg.BotID), len(msg.Denials))
		for _, d := range msg.Denials {
			text += fmt.Sprintf("\n• `%s %s`", slackEscape(d.Method), slackEscape(d.Pattern))
		}
	}
	if msg.Summary != "" {
		text += fmt.Sprintf("\n\n%s", slackEscape(msg.Summary))
	} else if len(msg.Denials) == 1 && msg.Reason != "" {
		text += fmt.Sprintf("\nReason: %s", slackEscape(msg.Reason))
	}
	if msg.URL != "" {
		text += fmt.Sprintf("\n<%s|View denials in CrabTrap>", slackEscapeURL(msg.URL))
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

func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func slackEscapeURL(s string) string {
	s = strings.ReplaceAll(s, ">", "%3E")
	s = strings.ReplaceAll(s, "|", "%7C")
	return s
}
