package judge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/brexhq/CrabTrap/pkg/types"
)

// JevCascadeDecidedBy marks a decision the LLM made after Jev was consulted
// first (escalation or Jev error). Jev-only decisions use "jev"; plain LLM
// decisions leave DecidedBy empty.
const JevCascadeDecidedBy = "jev+llm"

const (
	JevCascadeAllow    = "allow"
	JevCascadeDeny     = "deny"
	JevCascadeEscalate = "escalate"
	JevCascadeError    = "error"
	// JevCascadeSkipped means Jev was busy or its breaker was open, so the LLM
	// decided alone.
	JevCascadeSkipped = "skipped"
)

// JevCascadeObserver receives the cascade routing outcome. Implementations
// must be safe for concurrent use.
type JevCascadeObserver interface {
	OnJevCascade(outcome string)
}

// Scorer returns a JudgeResult whose Score holds p(violates) in [0,1]. A nil
// Score with a nil error is treated as a Jev error.
// *JevEvaluator is the production implementation.
type Scorer interface {
	Score(ctx context.Context, method, rawURL string, headers http.Header, body string, policy types.LLMPolicy) (JudgeResult, error)
}

var _ Scorer = (*JevEvaluator)(nil)

// JevCascadeEvaluator runs Jev first. Scores outside the uncertain band
// [AllowBelow, DenyAbove) make a fast Jev decision; uncertain scores and Jev
// errors fall through to the LLM evaluator.
type JevCascadeEvaluator struct {
	Primary    Scorer
	Secondary  Evaluator
	AllowBelow float64
	DenyAbove  float64
	Observer   JevCascadeObserver
}

// Compile-time check that JevCascadeEvaluator satisfies Evaluator.
var _ Evaluator = (*JevCascadeEvaluator)(nil)

// Evaluate implements Evaluator.
func (c *JevCascadeEvaluator) Evaluate(ctx context.Context, method, rawURL string, headers http.Header, body string, policy types.LLMPolicy) (JudgeResult, error) {
	if c.Secondary == nil {
		return JudgeResult{}, fmt.Errorf("jev cascade secondary evaluator is required")
	}
	// Without Jev this is a plain LLM decision, same as when Jev is unavailable.
	if c.Primary == nil {
		c.observe(JevCascadeSkipped)
		return c.Secondary.Evaluate(ctx, method, rawURL, headers, body, policy)
	}

	primary, err := c.Primary.Score(ctx, method, rawURL, headers, body, policy)
	if err == nil && primary.Score == nil {
		err = errors.New("jev returned no score")
	}
	if err != nil {
		// A caller that went away is not a Jev error: skip the error outcome,
		// the warning, and the LLM call.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return JudgeResult{}, ctxErr
		}
		// Jev never ran, so this is a plain LLM decision, not a Jev failure.
		if errors.Is(err, ErrJevUnavailable) {
			c.observe(JevCascadeSkipped)
			return c.Secondary.Evaluate(ctx, method, rawURL, headers, body, policy)
		}
		slog.Warn("Jev cascade scorer failed; escalating to LLM", "error", err)
		c.observe(JevCascadeError)
		return c.escalate(ctx, primary, err, method, rawURL, headers, body, policy)
	}
	switch noul := *primary.Score; {
	case noul < c.AllowBelow:
		primary.Decision = types.DecisionAllow
		primary.DecidedBy = "jev"
		primary.Reason = fmt.Sprintf("jev: p(violates)=%.2f < allow_below=%.2f", noul, c.AllowBelow)
		c.observe(JevCascadeAllow)
		return primary, nil
	case noul >= c.DenyAbove:
		primary.Decision = types.DecisionDeny
		primary.DecidedBy = "jev"
		primary.Reason = fmt.Sprintf("jev: p(violates)=%.2f >= deny_above=%.2f", noul, c.DenyAbove)
		c.observe(JevCascadeDeny)
		return primary, nil
	default:
		c.observe(JevCascadeEscalate)
		return c.escalate(ctx, primary, nil, method, rawURL, headers, body, policy)
	}
}

// escalate runs the LLM after Jev and folds Jev's cost into the result, so the
// persisted latency and tokens reflect everything the request paid for and the
// audit trail shows that both evaluators ran. jevErr is non-nil when Jev
// failed.
func (c *JevCascadeEvaluator) escalate(ctx context.Context, jev JudgeResult, jevErr error, method, rawURL string, headers http.Header, body string, policy types.LLMPolicy) (JudgeResult, error) {
	// With the caller gone the LLM call can only fail on the same context, and
	// the LLM adapter would count that against its circuit breaker.
	if err := ctx.Err(); err != nil {
		return JudgeResult{}, err
	}
	res, err := c.Secondary.Evaluate(ctx, method, rawURL, headers, body, policy)
	// Preserve the LLM error before adding Jev's prefix: the approval manager
	// only fills in error text when RawOutput is empty.
	if err != nil && res.RawOutput == "" {
		res.RawOutput = err.Error()
	}

	if jevErr != nil {
		// Error text can echo upstream details; keep only the kind of failure.
		jev.RawOutput = "jev: error, escalated to llm"
	} else {
		jev.RawOutput = fmt.Sprintf("jev noul p(violates)=%.4f, escalated to llm", *jev.Score)
	}
	if res.RawOutput != "" {
		res.RawOutput = jev.RawOutput + "\n" + res.RawOutput
	} else {
		res.RawOutput = jev.RawOutput
	}
	switch {
	case jev.Model != "" && res.Model != "":
		res.Model = jev.Model + " + " + res.Model
	case jev.Model != "":
		res.Model = jev.Model
	}
	res.DurationMs += jev.DurationMs
	res.InputTokens += jev.InputTokens
	res.OutputTokens += jev.OutputTokens
	res.DecidedBy = JevCascadeDecidedBy
	return res, err
}

func (c *JevCascadeEvaluator) observe(outcome string) {
	if c.Observer != nil {
		c.Observer.OnJevCascade(outcome)
	}
}
