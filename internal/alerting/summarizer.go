package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/brexhq/CrabTrap/internal/llm"
)

// LLMSummarizer uses an LLM to generate a summary of a batch of denials and,
// in the same pass, redact any secrets (API keys, tokens, passwords) that
// appear in the denied request URLs before they are shown to humans in Slack.
type LLMSummarizer struct {
	adapter llm.Adapter
}

func NewLLMSummarizer(adapter llm.Adapter) *LLMSummarizer {
	return &LLMSummarizer{adapter: adapter}
}

// summarizerOutput is the JSON the model is asked to return: a plain-text
// summary plus the redacted form of each denied URL, in the same order as the
// denials passed in.
type summarizerOutput struct {
	Summary string   `json:"summary"`
	URLs    []string `json:"urls"`
}

// Summarize returns a human-readable summary and a copy of denials whose URLs
// have had secrets redacted by the LLM. Callers must use the returned denials
// (not the originals) for anything that leaves the system: the originals still
// contain live credentials. An error is returned if the LLM is unavailable or
// returns output that cannot be trusted to be fully redacted.
func (s *LLMSummarizer) Summarize(ctx context.Context, botID string, denials []DenialInfo) (string, []DenialInfo, error) {
	if len(denials) == 0 {
		return "", nil, nil
	}
	if s.adapter == nil {
		return "", nil, fmt.Errorf("alerting: no LLM adapter configured for summarization")
	}

	var lines []string
	for i, d := range denials {
		line := fmt.Sprintf("%d. %s %s", i+1, d.Method, d.URL)
		if d.Reason != "" {
			line += fmt.Sprintf(" (denied because: %s)", d.Reason)
		}
		lines = append(lines, line)
	}

	prompt := fmt.Sprintf(
		"A bot (%s) had %d HTTP requests denied by a security policy in the last few minutes:\n\n%s\n\n"+
			"Do two things and return them as a single JSON object:\n"+
			"1. \"summary\": 2-3 sentences describing what the bot was trying to do and why it was blocked. "+
			"If this looks like a legitimate workflow that needs policy access, say so; if it looks suspicious or "+
			"like a hallucination, flag that. Be specific and actionable for an engineering manager deciding whether "+
			"to update the policy. Plain text only — no markdown.\n"+
			"2. \"urls\": an array with the redacted URL from each numbered request line above, in the same order "+
			"(%d entries, just the URL — omit the method). Redact every secret in the URL — API keys, tokens, "+
			"passwords, client secrets, session IDs, or any high-entropy credential-like value, whether in the "+
			"query string (e.g. api_key=, token=, *_secret=) or the userinfo component — by replacing the secret "+
			"value with [REDACTED]. Keep the path and non-secret query parameters intact. Redact any "+
			"secrets in the \"summary\" field too.\n\n"+
			"Return ONLY the JSON object: {\"summary\": \"...\", \"urls\": [\"https://...\", ...]}",
		botID, len(denials), strings.Join(lines, "\n"), len(denials),
	)

	resp, err := s.adapter.Complete(ctx, llm.Request{
		System:    "You analyze AI agent denial events for engineering managers and redact secrets before they are shown to humans. Output only the requested JSON object.",
		Messages:  []llm.Message{{Role: "user", Content: prompt}},
		MaxTokens: 1500,
	})
	if err != nil {
		return "", nil, err
	}

	var out summarizerOutput
	if err := json.Unmarshal([]byte(llm.StripCodeFences(resp.Text)), &out); err != nil {
		return "", nil, fmt.Errorf("alerting: parse summarizer output: %w", err)
	}
	if len(out.URLs) != len(denials) {
		return "", nil, fmt.Errorf("alerting: summarizer returned %d urls for %d denials", len(out.URLs), len(denials))
	}

	redacted := make([]DenialInfo, len(denials))
	for i, d := range denials {
		d.URL = strings.TrimSpace(out.URLs[i])
		redacted[i] = d
	}

	return strings.TrimSpace(out.Summary), redacted, nil
}
