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

// newRunnerWithFixedScores wires a Runner to an httptest server that always
// returns the given per-probe per-token score map.
func newRunnerWithFixedScores(t *testing.T, specs []Spec, maxBody int, scores map[string][]float64) (*Runner, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(scores))
	}))
	c := NewClient(server.URL, "test-model", 5*time.Second, 32)
	return NewRunner(c, specs, maxBody), server
}

func TestRunner_NoTrip_AllBelowThreshold(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.8, Aggregation: "max"}},
		0,
		map[string][]float64{"exfiltration": {0.1, 0.2, 0.3}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip, got %q", result.Tripped)
	}
	if got := result.Scores["exfiltration"]; got != 0.3 {
		t.Errorf("expected aggregated score 0.3, got %v", got)
	}
}

func TestRunner_Trips_MaxAggregation(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.7, Aggregation: "max"}},
		0,
		map[string][]float64{"exfiltration": {0.1, 0.9, 0.3}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "POST", "https://example.com/api", http.Header{}, `{"data":"secret"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "exfiltration" {
		t.Errorf("expected trip on exfiltration, got %q", result.Tripped)
	}
	if result.Aggregation != "max" {
		t.Errorf("expected aggregation=max, got %q", result.Aggregation)
	}
	if got := result.Scores["exfiltration"]; got != 0.9 {
		t.Errorf("expected aggregated score 0.9, got %v", got)
	}
}

func TestRunner_MeanAggregation(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "jailbreak", Threshold: 0.5, Aggregation: "mean"}},
		0,
		map[string][]float64{"jailbreak": {0.4, 0.6, 0.8}}, // mean = 0.6, trips
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "jailbreak" {
		t.Errorf("expected trip on jailbreak, got %q", result.Tripped)
	}
	if got := result.Scores["jailbreak"]; got < 0.59 || got > 0.61 {
		t.Errorf("expected mean ≈ 0.6, got %v", got)
	}
}

func TestRunner_FirstTripWins(t *testing.T) {
	// jailbreak configured first; both trip, but Tripped should be jailbreak.
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "jailbreak", Threshold: 0.5, Aggregation: "max"},
			{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"},
		},
		0,
		map[string][]float64{
			"jailbreak":    {0.9},
			"exfiltration": {0.95},
		},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "jailbreak" {
		t.Errorf("expected first configured probe to trip, got %q", result.Tripped)
	}
	if len(result.Scores) != 2 {
		t.Errorf("expected both probes' scores recorded, got %v", result.Scores)
	}
}

func TestRunner_EmptyScoreArray_NoTrip(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.1, Aggregation: "max"}},
		0,
		map[string][]float64{"exfiltration": {}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip for empty score array, got %q", result.Tripped)
	}
	if got := result.Scores["exfiltration"]; got != 0.0 {
		t.Errorf("expected score 0.0 for empty array, got %v", got)
	}
}

func TestRunner_MissingProbe_RecordsZero(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{
			{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"},
			{Name: "jailbreak", Threshold: 0.5, Aggregation: "max"},
		},
		0,
		map[string][]float64{"exfiltration": {0.3}}, // jailbreak absent
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "" {
		t.Errorf("expected no trip, got %q", result.Tripped)
	}
	if got, ok := result.Scores["jailbreak"]; !ok || got != 0.0 {
		t.Errorf("missing probe should record as 0.0, got %v (ok=%v)", got, ok)
	}
}

func TestRunner_DefaultAggregationIsMax(t *testing.T) {
	r, server := newRunnerWithFixedScores(t,
		[]Spec{{Name: "exfiltration", Threshold: 0.7}}, // no Aggregation set
		0,
		map[string][]float64{"exfiltration": {0.1, 0.9, 0.3}},
	)
	defer server.Close()

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Tripped != "exfiltration" {
		t.Errorf("expected trip, got %q", result.Tripped)
	}
	if result.Aggregation != "max" {
		t.Errorf("expected default aggregation=max, got %q", result.Aggregation)
	}
}

func TestRunner_CircuitOpen_ReturnsFlagWithoutError(t *testing.T) {
	// Server always 500s; after 3 failures the breaker trips.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", 1*time.Second, 32,
		llm.WithCircuitBreaker(3, 1*time.Hour),
	)
	r := NewRunner(c, []Spec{{Name: "exfiltration", Threshold: 0.5, Aggregation: "max"}}, 0)

	for i := 0; i < 3; i++ {
		// Pre-warm the breaker with real failing calls via the client directly.
		c.Complete(context.Background(), "sys", "user") //nolint:errcheck
	}
	if !c.IsOpen() {
		t.Fatal("precondition: expected circuit breaker to be open")
	}

	result, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err != nil {
		t.Fatalf("Evaluate should swallow circuit-open; got err %v", err)
	}
	if !result.CircuitOpen {
		t.Error("expected result.CircuitOpen=true")
	}
	if result.Tripped != "" {
		t.Error("expected no trip when circuit is open")
	}
}

func TestRunner_HTTPError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", 1*time.Second, 32)
	r := NewRunner(c, []Spec{{Name: "exfiltration", Threshold: 0.5}}, 0)

	_, err := r.Evaluate(context.Background(), "GET", "https://example.com", http.Header{}, "")
	if err == nil {
		t.Fatal("expected error on HTTP 502")
	}
	if !strings.Contains(err.Error(), "probe client complete failed") {
		t.Errorf("error should wrap client failure, got %v", err)
	}
}

func TestRunner_UsesJudgepromptBuildUserMessage(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(probeSuccessResponse(map[string][]float64{}))
	}))
	defer server.Close()

	c := NewClient(server.URL, "test-model", 5*time.Second, 32)
	r := NewRunner(c, nil, 0)

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	_, err := r.Evaluate(context.Background(), "POST", "https://api.example.com/v1/x", headers, `{"k":"v"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var body struct {
		Messages []struct{ Role, Content string }
	}
	if err := json.Unmarshal(capturedBody, &body); err != nil {
		t.Fatalf("failed to parse body: %v", err)
	}
	if len(body.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(body.Messages))
	}
	// The user message should be JSON built by judgeprompt with method + URL.
	if !strings.Contains(body.Messages[1].Content, `"method":"POST"`) {
		t.Errorf("user message missing method: %s", body.Messages[1].Content)
	}
	if !strings.Contains(body.Messages[1].Content, `"url":"https://api.example.com/v1/x"`) {
		t.Errorf("user message missing url: %s", body.Messages[1].Content)
	}
}

func TestAggregate(t *testing.T) {
	cases := []struct {
		name   string
		tokens []float64
		method string
		want   float64
	}{
		{"empty max", nil, "max", 0.0},
		{"empty mean", []float64{}, "mean", 0.0},
		{"single max", []float64{0.7}, "max", 0.7},
		{"max picks highest", []float64{0.1, 0.9, 0.3}, "max", 0.9},
		{"mean averages", []float64{0.2, 0.4, 0.6}, "mean", 0.4},
		{"unknown method falls back to max", []float64{0.1, 0.5, 0.3}, "bogus", 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := aggregate(tc.tokens, tc.method)
			if got < tc.want-1e-9 || got > tc.want+1e-9 {
				t.Errorf("aggregate(%v, %q) = %v, want %v", tc.tokens, tc.method, got, tc.want)
			}
		})
	}
}
