package judge

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/brexhq/CrabTrap/pkg/types"
)

const (
	JevCascadeAllow    = "allow"
	JevCascadeDeny     = "deny"
	JevCascadeEscalate = "escalate"
	JevCascadeError    = "error"
)

// JevCascadeObserver receives the cascade routing outcome. Implementations
// must be safe for concurrent use.
type JevCascadeObserver interface {
	OnJevCascade(outcome string)
}

// Scorer returns a JudgeResult whose Score holds p(violates) in [0,1].
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
	if c.Primary == nil {
		c.observe(JevCascadeEscalate)
		return c.Secondary.Evaluate(ctx, method, rawURL, headers, body, policy)
	}

	primary, err := c.Primary.Score(ctx, method, rawURL, headers, body, policy)
	if err != nil || primary.Score == nil {
		if err != nil {
			slog.Warn("Jev cascade scorer failed; escalating to LLM", "error", err)
		} else {
			slog.Warn("Jev cascade scorer returned no score; escalating to LLM")
		}
		c.observe(JevCascadeError)
		return c.Secondary.Evaluate(ctx, method, rawURL, headers, body, policy)
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
		return c.Secondary.Evaluate(ctx, method, rawURL, headers, body, policy)
	}
}

func (c *JevCascadeEvaluator) observe(outcome string) {
	if c.Observer != nil {
		c.Observer.OnJevCascade(outcome)
	}
}
