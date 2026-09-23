package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// f64ptr returns a pointer to v, for building jevAnswer literals whose Noul
// field is now *float64 (so a missing "noul" field in a real response can be
// distinguished from an explicit 0.0).
func f64ptr(v float64) *float64 { return &v }

func newTestJevEvaluator(t *testing.T, serverURL string) *JevEvaluator {
	t.Helper()
	j, err := NewJevEvaluator("test-key", 5*time.Second)
	if err != nil {
		t.Fatalf("NewJevEvaluator: %v", err)
	}
	j.SetBaseURL(serverURL)
	return j
}

func TestJevEvaluator_Score(t *testing.T) {
	var capturedAuth string
	var capturedBody jevRequest
	var decodeErr error

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		decodeErr = json.NewDecoder(r.Body).Decode(&capturedBody)
		resp := jevResponse{
			Model:   jevModel,
			Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(0.05)}},
			Usage:   jevUsage{InputTokens: 100, OutputTokens: 10},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	result, err := j.Score(context.Background(), "GET", "https://example.com/api", http.Header{}, "", types.LLMPolicy{Prompt: "allow all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decodeErr != nil {
		t.Fatalf("decode request body: %v", decodeErr)
	}
	if got := capturedAuth; got != "Bearer test-key" {
		t.Errorf("Authorization header = %q, want Bearer test-key", got)
	}
	if capturedBody.Model != jevModel {
		t.Errorf("Model = %q, want %q", capturedBody.Model, jevModel)
	}
	if !strings.Contains(capturedBody.State, "allow all") {
		t.Errorf("State should contain policy prompt, got: %s", capturedBody.State)
	}
	q, ok := capturedBody.Questions[jevViolatesQuestionKey]
	if !ok {
		t.Fatalf("request missing question %q", jevViolatesQuestionKey)
	}
	if q.Type != "noul" {
		t.Errorf("Questions[%q].Type = %q, want %q", jevViolatesQuestionKey, q.Type, "noul")
	}

	if result.Score == nil || *result.Score != 0.05 {
		t.Errorf("Score = %v, want 0.05", result.Score)
	}
	if result.InputTokens != 100 || result.OutputTokens != 10 {
		t.Errorf("token counts not populated: %+v", result)
	}
	if result.Reason == "" {
		t.Error("Reason should be synthesized from the probability")
	}
}

func TestJevEvaluator_ScoreIsNotAnApprovalDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jevResponse{
			Model:   jevModel,
			Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(0.93)}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	result, err := j.Score(context.Background(), "POST", "https://example.com/api", http.Header{}, `{"x":1}`, types.LLMPolicy{Prompt: "deny writes"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != "" {
		t.Errorf("Decision = %v, want no approval decision", result.Decision)
	}
}

func TestJevEvaluator_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key","state":"secret-policy Authorization: Bearer sk-live"}`))
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	// The error is logged by the cascade, so it must not echo the upstream
	// body (which can contain the policy and request headers/body).
	if strings.Contains(err.Error(), "secret-policy") || strings.Contains(err.Error(), "sk-live") {
		t.Fatalf("error leaks upstream body: %v", err)
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("error = %v, want status code", err)
	}
}

func TestJevEvaluator_MissingAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jevResponse{Model: jevModel, Answers: map[string]jevAnswer{}})
	}))
	defer srv.Close()

	j := newTestJevEvaluator(t, srv.URL)
	_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err == nil {
		t.Fatal("expected error when answer is missing")
	}
}

// TestJevEvaluator_MissingNoulField ensures a well-formed answer that is
// missing the "noul" field (or carries the wrong answer type) is treated as
// an error rather than silently zero-valuing to a confident ALLOW.
func TestJevEvaluator_MissingNoulField(t *testing.T) {
	tests := []struct {
		name   string
		answer jevAnswer
	}{
		{"nil noul", jevAnswer{Type: "noul", Noul: nil}},
		{"wrong type", jevAnswer{Type: "bool", Noul: f64ptr(0.05)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(jevResponse{
					Model:   jevModel,
					Answers: map[string]jevAnswer{jevViolatesQuestionKey: tt.answer},
				})
			}))
			defer srv.Close()

			j := newTestJevEvaluator(t, srv.URL)
			_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
			if err == nil {
				t.Fatal("expected error for invalid noul answer, got nil (would silently become ALLOW)")
			}
		})
	}
}

func TestJevEvaluator_RejectsOutOfRangeScore(t *testing.T) {
	for _, score := range []float64{-0.01, 1.01} {
		t.Run(fmt.Sprintf("%v", score), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(jevResponse{
					Model:   jevModel,
					Answers: map[string]jevAnswer{jevViolatesQuestionKey: {Type: "noul", Noul: f64ptr(score)}},
				})
			}))
			defer srv.Close()

			j := newTestJevEvaluator(t, srv.URL)
			_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
			if err == nil {
				t.Fatal("expected error for out-of-range score")
			}
		})
	}
}

func TestNewJevEvaluator_RequiresAPIKey(t *testing.T) {
	if _, err := NewJevEvaluator("", time.Second); err == nil {
		t.Fatal("expected error for empty API key")
	}
}

func TestJevEvaluatorHonorsResilienceOptions(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		http.Error(w, "upstream failure", http.StatusInternalServerError)
	}))
	defer srv.Close()

	j, err := NewJevEvaluator("test-key", time.Second,
		llm.WithMaxConcurrency(1),
		llm.WithCircuitBreaker(1, time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	j.SetBaseURL(srv.URL)

	firstDone := make(chan error, 1)
	go func() {
		_, err := j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
		firstDone <- err
	}()
	<-started

	// With the only slot taken, a second call must fail fast instead of
	// queueing, so the cascade can escalate to the LLM without added latency.
	secondStart := time.Now()
	_, err = j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err == nil || !strings.Contains(err.Error(), "max concurrency") {
		t.Fatalf("second call error = %v, want max concurrency", err)
	}
	if elapsed := time.Since(secondStart); elapsed > 100*time.Millisecond {
		t.Fatalf("second call took %v, want immediate failure", elapsed)
	}
	select {
	case <-started:
		t.Fatal("second call reached Jev despite max concurrency of one")
	default:
	}

	close(release)
	if err := <-firstDone; err == nil {
		t.Fatal("first call should return the upstream error")
	}
	_, err = j.Score(context.Background(), "GET", "https://example.com", http.Header{}, "", types.LLMPolicy{Prompt: "p"})
	if err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
		t.Fatalf("third call error = %v, want circuit breaker open", err)
	}
}
