// Package probes calls probe-demo (an OpenAI-compatible inference server
// that returns per-token activation scores from trained policy heads) and
// turns those scores into ALLOW/DENY signal for the approval pipeline.
package probes

// Spec configures one probe: its name (must match what probe-demo returns in
// the scores map), the trip threshold in [0, 1], and how per-token scores
// collapse to a single number ("max" | "mean").
type Spec struct {
	Name        string
	Threshold   float64
	Aggregation string
}

// Result is the outcome of one Runner.Evaluate call. Scores holds the
// aggregated score per probe name (empty when the probe call failed or the
// circuit breaker was open). Tripped is the name of the first probe that
// exceeded its threshold, or "" when none tripped. Aggregation repeats the
// method used (for audit logging); callers should not mix methods within
// one Result. CircuitOpen is true when the probe circuit breaker rejected
// the call without hitting probe-demo.
type Result struct {
	Scores      map[string]float64
	Tripped     string
	Aggregation string
	CircuitOpen bool
}
