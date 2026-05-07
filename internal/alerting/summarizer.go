package alerting

import (
	"context"
	"fmt"
	"strings"

	"github.com/brexhq/CrabTrap/internal/llm"
)

// LLMSummarizer uses an LLM to generate a human-readable summary of what a bot
// was trying to do when it was denied. Returns empty string on any error.
type LLMSummarizer struct {
	adapter llm.Adapter
}

func NewLLMSummarizer(adapter llm.Adapter) *LLMSummarizer {
	return &LLMSummarizer{adapter: adapter}
}

func (s *LLMSummarizer) Summarize(ctx context.Context, botID, method, pattern, reason string) (string, error) {
	if s.adapter == nil {
		return "", nil
	}

	prompt := fmt.Sprintf(
		"A bot (%s) made an HTTP request that was denied by a security policy.\n"+
			"Request: %s %s\n"+
			"Denial reason: %s\n\n"+
			"In 1-2 sentences, explain what the bot was likely trying to do and why it was blocked. "+
			"Be specific and actionable — a manager will read this to decide whether to update the policy.",
		botID, method, pattern, reason,
	)

	resp, err := s.adapter.Complete(ctx, llm.Request{
		System:    "You summarize AI agent denial events concisely for engineering managers.",
		Messages:  []llm.Message{{Role: "user", Content: prompt}},
		MaxTokens: 150,
	})
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(resp.Text), nil
}
