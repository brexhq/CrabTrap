package probes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
)

func probeSuccessResponse(scores map[string][]float64) []byte {
	resp := map[string]interface{}{
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   "test-model",
		"choices": []map[string]interface{}{{
			"index": 0,
			"message": map[string]interface{}{
				"role":    "assistant",
				"content": "The request fetches a public homepage.",
			},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{
			"prompt_tokens":     42,
			"completion_tokens": 7,
			"total_tokens":      49,
		},
		"scores": scores,
	}
	b, _ := json.Marshal(resp)
	return b
}

func newTestClient(t *testing.T, serverURL string) *Client {
	t.Helper()
	return NewClient(serverURL, "test-model", 5*time.Second, 32)
}

func TestClientComplete_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{
			"exfiltration": {0.1, 0.2, 0.15},
			"jailbreak":    {0.05, 0.08},
		}))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	resp, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Scores) != 2 {
		t.Errorf("expected 2 probe entries, got %d", len(resp.Scores))
	}
	if got := resp.Scores["exfiltration"]; len(got) != 3 {
		t.Errorf("expected 3 exfiltration scores, got %v", got)
	}
	if resp.InputTokens != 42 || resp.OutputTokens != 7 {
		t.Errorf("usage fields not set: %+v", resp)
	}
	if resp.DurationMs <= 0 {
		t.Errorf("DurationMs should be > 0, got %d", resp.DurationMs)
	}
}

func TestClientComplete_SendsIncludeScoresAndMessages(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{}))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	if _, err := c.Complete(context.Background(), "system-prompt", "user-msg"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed struct {
		Model         string `json:"model"`
		Messages      []struct{ Role, Content string }
		Stream        bool `json:"stream"`
		MaxTokens     int  `json:"max_tokens"`
		IncludeScores bool `json:"include_scores"`
	}
	if err := json.Unmarshal(capturedBody, &parsed); err != nil {
		t.Fatalf("failed to parse captured body: %v\nbody=%s", err, capturedBody)
	}
	if !parsed.IncludeScores {
		t.Error("include_scores should be true")
	}
	if parsed.Stream {
		t.Error("stream should be false")
	}
	if parsed.MaxTokens != 32 {
		t.Errorf("max_tokens = %d, want 32", parsed.MaxTokens)
	}
	if parsed.Model != "test-model" {
		t.Errorf("model = %q, want test-model", parsed.Model)
	}
	if len(parsed.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(parsed.Messages))
	}
	if parsed.Messages[0].Role != "system" || parsed.Messages[0].Content != "system-prompt" {
		t.Errorf("system message wrong: %+v", parsed.Messages[0])
	}
	if parsed.Messages[1].Role != "user" || parsed.Messages[1].Content != "user-msg" {
		t.Errorf("user message wrong: %+v", parsed.Messages[1])
	}
}

func TestClientComplete_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"boom"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	_, err := c.Complete(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("error should mention status 500, got %v", err)
	}
}

func TestClientComplete_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	_, err := c.Complete(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestClientComplete_EmptyScoresMap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(nil))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	resp, err := c.Complete(context.Background(), "sys", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Scores != nil && len(resp.Scores) != 0 {
		t.Errorf("expected empty/nil scores, got %v", resp.Scores)
	}
}

func TestClientComplete_CircuitBreakerTrips(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", 1*time.Second, 32,
		llm.WithCircuitBreaker(3, 1*time.Hour),
	)

	for i := 0; i < 3; i++ {
		if _, err := c.Complete(context.Background(), "sys", "user"); err == nil {
			t.Fatalf("call %d: expected error, got nil", i)
		}
	}
	if !c.IsOpen() {
		t.Fatal("expected circuit breaker to be open after 3 failures")
	}

	_, err := c.Complete(context.Background(), "sys", "user")
	if err == nil {
		t.Fatal("expected circuit-open error")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected circuit breaker open error, got %v", err)
	}
}
