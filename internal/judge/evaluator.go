package judge

import (
	"context"
	"net/http"

	"github.com/brexhq/CrabTrap/pkg/types"
)

// Evaluator is anything that can allow/deny an HTTP request against a policy
// (an LLM judge or a cascade that wraps one).
type Evaluator interface {
	Evaluate(ctx context.Context, method, rawURL string, headers http.Header, body string, policy types.LLMPolicy) (JudgeResult, error)
}

// Compile-time check that LLMJudge satisfies Evaluator.
var _ Evaluator = (*LLMJudge)(nil)
