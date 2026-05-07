package alerting

import (
	"context"
	"fmt"
	"strings"

	"github.com/brexhq/CrabTrap/internal/llm"
)

// LLMSummarizer uses an LLM to generate a human-readable summary of what a bot
// was trying to do when it was denied. Accepts a batch of denials so it can
// identify multi-request operations. Returns empty string on any error.
type LLMSummarizer struct {
	adapter llm.Adapter
}

func NewLLMSummarizer(adapter llm.Adapter) *LLMSummarizer {
	return &LLMSummarizer{adapter: adapter}
}

func (s *LLMSummarizer) Summarize(ctx context.Context, botID string, denials []DenialInfo) (string, error) {
	if s.adapter == nil || len(denials) == 0 {
		return "", nil
	}

	var lines []string
	for _, d := range denials {
		line := fmt.Sprintf("- %s %s", d.Method, d.Pattern)
		if d.Reason != "" {
			line += fmt.Sprintf(" (reason: %s)", d.Reason)
		}
		lines = append(lines, line)
	}

	prompt := fmt.Sprintf(
		"A bot (%s) made HTTP requests that were denied by a security policy:\n\n%s\n\n"+
			"In 1-2 sentences, explain what the bot was likely trying to do as a whole and why it was blocked. "+
			"Be specific and actionable — a manager will read this to decide whether to update the policy.",
		botID, strings.Join(lines, "\n"),
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
