package alerting

import (
	"context"
	"fmt"
	"strings"

	"github.com/brexhq/CrabTrap/internal/llm"
)

// LLMSummarizer uses an LLM to generate a summary of a batch of denials.
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
		line := fmt.Sprintf("- %s %s", d.Method, d.URL)
		if d.Reason != "" {
			line += fmt.Sprintf(" (denied because: %s)", d.Reason)
		}
		lines = append(lines, line)
	}

	prompt := fmt.Sprintf(
		"A bot (%s) had %d HTTP requests denied by a security policy in the last few minutes:\n\n%s\n\n"+
			"Summarize in 2-3 sentences: what was the bot trying to do, and why was it blocked? "+
			"If this looks like a legitimate workflow that needs policy access, say so. "+
			"If it looks suspicious or like a hallucination, flag that. "+
			"Be specific and actionable for an engineering manager deciding whether to update the policy. "+
			"Use plain text only — no markdown, no bullet points, no bold/italic formatting.",
		botID, len(denials), strings.Join(lines, "\n"),
	)

	resp, err := s.adapter.Complete(ctx, llm.Request{
		System:    "You analyze AI agent denial events for engineering managers. Be concise and actionable. Output plain text only, no markdown formatting.",
		Messages:  []llm.Message{{Role: "user", Content: prompt}},
		MaxTokens: 200,
	})
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(resp.Text), nil
}
