package probes

import (
	"context"
	"fmt"
	"net/http"

	"github.com/brexhq/CrabTrap/internal/judgeprompt"
)

// DefaultMaxBodyBytes is the probe-specific body cap — half the judge's cap
// (16384) to bound probe-demo forward-pass cost. Operators can override via
// config.
const DefaultMaxBodyBytes = 8192

// Aggregation methods for collapsing per-token scores to a single number.
const (
	AggregationMax  = "max"
	AggregationMean = "mean"
)

// probeSystemPrompt is intentionally minimal. Probes activate on the model's
// semantic understanding of the request, not on a decision output, so asking
// for a structured verdict (as the judge does) would mislead the probe heads.
// A one-sentence description gives the model enough tokens to surface signal.
//
// The exact wording is placeholder and expected to need tuning against real
// traffic once probes are deployed.
const probeSystemPrompt = `You are analyzing an HTTP request made by an AI agent. In one sentence, describe what this request is attempting to do.`

// Runner orchestrates a probe-demo call and reduces the returned per-token
// scores into a pass/trip decision.
type Runner struct {
	client       *Client
	specs        []Spec
	maxBodyBytes int
}

// NewRunner wraps a Client with the configured probe specs and body cap. A
// non-positive maxBodyBytes falls back to DefaultMaxBodyBytes.
func NewRunner(client *Client, specs []Spec, maxBodyBytes int) *Runner {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	return &Runner{
		client:       client,
		specs:        specs,
		maxBodyBytes: maxBodyBytes,
	}
}

// Evaluate serializes the HTTP request, calls probe-demo, aggregates per-token
// scores per Spec, and reports the first probe whose aggregated score meets
// or exceeds its threshold.
//
// When the circuit breaker is open, Evaluate returns a Result with
// CircuitOpen=true and nil error so the caller can log the degraded state
// and fall through to the judge path. Other errors (HTTP failure, bad JSON)
// return a zero Result plus the error.
func (r *Runner) Evaluate(ctx context.Context, method, rawURL string, headers http.Header, body string) (Result, error) {
	if r.client.IsOpen() {
		return Result{CircuitOpen: true}, nil
	}

	userMsg := judgeprompt.BuildUserMessage(method, rawURL, headers, body, r.maxBodyBytes)
	resp, err := r.client.Complete(ctx, probeSystemPrompt, userMsg)
	if err != nil {
		return Result{}, fmt.Errorf("probe client complete failed: %w", err)
	}

	aggregated := make(map[string]float64, len(r.specs))
	var tripped, trippedAggregation string
	for _, spec := range r.specs {
		agg := spec.Aggregation
		if agg == "" {
			agg = AggregationMax
		}
		score := aggregate(resp.Scores[spec.Name], agg)
		aggregated[spec.Name] = score
		if tripped == "" && score >= spec.Threshold {
			tripped = spec.Name
			trippedAggregation = agg
		}
	}

	return Result{
		Scores:      aggregated,
		Tripped:     tripped,
		Aggregation: trippedAggregation,
	}, nil
}

// aggregate collapses a per-token score slice to a single value. Empty input
// (e.g. probe-demo returned completion_tokens: 0, or the probe name is not
// in the response) returns 0.0, which can never trip a non-zero threshold.
func aggregate(tokens []float64, method string) float64 {
	if len(tokens) == 0 {
		return 0.0
	}
	switch method {
	case AggregationMean:
		var sum float64
		for _, v := range tokens {
			sum += v
		}
		return sum / float64(len(tokens))
	default: // "max" is the default and fallback.
		m := tokens[0]
		for _, v := range tokens[1:] {
			if v > m {
				m = v
			}
		}
		return m
	}
}
