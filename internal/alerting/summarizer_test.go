package alerting

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/brexhq/CrabTrap/internal/llm"
)

func TestSummarize_RedactsSecretsAndReturnsRedactedURLs(t *testing.T) {
	var prompt string
	s := NewLLMSummarizer(&llm.TestAdapter{
		Fn: func(req llm.Request) (llm.Response, error) {
			prompt = req.Messages[0].Content
			return llm.Response{Text: `{"summary":"The bot tried to list email accounts and was blocked.","urls":["https://server.smartlead.ai/api/v1/email-accounts/?api_key=[REDACTED]&limit=100"]}`}, nil
		},
	})

	denials := []DenialInfo{{
		Method: "GET",
		URL:    "https://server.smartlead.ai/api/v1/email-accounts/?api_key=super-secret&limit=100",
		Reason: "domain not allowed",
	}}

	summary, redacted, err := s.Summarize(context.Background(), "bot@example.com", denials)
	if err != nil {
		t.Fatal(err)
	}
	if len(redacted) != 1 {
		t.Fatalf("expected 1 redacted denial, got %d", len(redacted))
	}
	if strings.Contains(redacted[0].URL, "super-secret") {
		t.Fatalf("api_key leaked in redacted URL: %q", redacted[0].URL)
	}
	if redacted[0].Method != "GET" || redacted[0].Reason != "domain not allowed" {
		t.Fatalf("method/reason not preserved: %+v", redacted[0])
	}
	if strings.Contains(summary, "super-secret") {
		t.Fatalf("api_key leaked in summary: %q", summary)
	}
	// The raw secret is still sent to the LLM (it must see it to redact it),
	// but that is the trusted redaction boundary, not an external surface.
	if !strings.Contains(prompt, "super-secret") {
		t.Fatalf("expected raw URL in LLM prompt, got %q", prompt)
	}
}

func TestSummarize_ErrorOnCountMismatch(t *testing.T) {
	s := NewLLMSummarizer(&llm.TestAdapter{
		Fn: func(llm.Request) (llm.Response, error) {
			// Returns fewer URLs than denials — must not be trusted.
			return llm.Response{Text: `{"summary":"ok","urls":[]}`}, nil
		},
	})

	denials := []DenialInfo{
		{Method: "GET", URL: "https://example.com/?token=abc"},
		{Method: "GET", URL: "https://example.com/?token=def"},
	}
	if _, _, err := s.Summarize(context.Background(), "bot", denials); err == nil {
		t.Fatal("expected error on url/denial count mismatch")
	}
}

func TestSummarize_ErrorOnAdapterFailure(t *testing.T) {
	s := NewLLMSummarizer(&llm.TestAdapter{
		Fn: func(llm.Request) (llm.Response, error) {
			return llm.Response{}, errors.New("llm down")
		},
	})

	denials := []DenialInfo{{Method: "GET", URL: "https://example.com/?api_key=secret"}}
	if _, _, err := s.Summarize(context.Background(), "bot", denials); err == nil {
		t.Fatal("expected error when adapter fails")
	}
}

func TestSummarize_NoAdapter(t *testing.T) {
	s := NewLLMSummarizer(nil)
	if _, _, err := s.Summarize(context.Background(), "bot", []DenialInfo{{URL: "x"}}); err == nil {
		t.Fatal("expected error when no adapter is configured")
	}
}

func TestSummarize_StripsCodeFences(t *testing.T) {
	s := NewLLMSummarizer(&llm.TestAdapter{
		Fn: func(_ llm.Request) (llm.Response, error) {
			return llm.Response{Text: "```json\n{\"summary\":\"ok\",\"urls\":[\"https://example.com/\"]}\n```"}, nil
		},
	})
	_, redacted, err := s.Summarize(context.Background(), "bot", []DenialInfo{{Method: "GET", URL: "https://example.com/?token=x"}})
	if err != nil {
		t.Fatalf("expected fenced JSON to parse, got %v", err)
	}
	if len(redacted) != 1 || redacted[0].URL != "https://example.com/" {
		t.Fatalf("unexpected redacted denials: %+v", redacted)
	}
}
