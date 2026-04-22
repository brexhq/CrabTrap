package approval

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

// ContextKeyUserID is the context key used to pass the gateway user ID into CheckApproval.
const ContextKeyUserID contextKey = "user_id"

// ContextKeyLLMPolicy is the context key used to pass the per-user LLMPolicy into CheckApproval.
const ContextKeyLLMPolicy contextKey = "llm_policy"

// ContextKeyOriginalHeaders carries the request headers for the LLM judge evaluation.
const ContextKeyOriginalHeaders contextKey = "original_headers"

// ContextKeyOriginalBody carries the request body for the LLM judge evaluation.
const ContextKeyOriginalBody contextKey = "original_body"

// ContextKeyBufferedBody carries the raw request body bytes already buffered by
// the proxy. When present, CheckApproval must not read req.Body again because
// large uploads may still have an unread streaming tail attached to req.Body.
const ContextKeyBufferedBody contextKey = "buffered_body"

// Manager orchestrates the approval decision flow
type Manager struct {
	judge        *judge.LLMJudge // nil if LLM mode disabled
	mode         string          // "llm" | "passthrough"
	fallbackMode string          // "deny" | "passthrough"

}

// NewManager creates a new approval manager.
func NewManager() *Manager {
	return &Manager{
		mode: "llm",
	}
}

// SetMode configures the approval mode used by CheckApproval.
func (m *Manager) SetMode(mode string) {
	if mode == "" {
		mode = "llm"
	}
	m.mode = mode
}

// SetJudge configures the LLM judge and switches the manager to the given mode.
func (m *Manager) SetJudge(j *judge.LLMJudge, mode, fallbackMode string) {
	m.judge = j
	m.SetMode(mode)
	m.fallbackMode = fallbackMode
}

// CheckApproval checks if a request should be allowed.
// In "llm" mode every request (including GET) is evaluated by the LLM judge; no caching.
// In "passthrough" mode every request is auto-approved.
func (m *Manager) CheckApproval(ctx context.Context, req *http.Request, requestID string, apiInfo *types.APIInfo) (types.ApprovalDecision, []byte, error) {
	if m.mode == "passthrough" {
		return types.ApprovalDecision{
			Decision:   types.DecisionAllow,
			ApprovedBy: "passthrough",
			Channel:    "passthrough",
			Reason:     "passthrough mode",
		}, nil, nil
	}
	if m.judge != nil {
		return m.checkApprovalLLM(ctx, req, requestID, apiInfo)
	}
	return types.ApprovalDecision{
		Decision:   types.DecisionDeny,
		ApprovedBy: "system",
		Channel:    "system",
		Reason:     "llm judge not configured",
	}, nil, nil
}

// checkApprovalLLM evaluates the request with the LLM judge.
func (m *Manager) checkApprovalLLM(ctx context.Context, req *http.Request, requestID string, apiInfo *types.APIInfo) (types.ApprovalDecision, []byte, error) {
	body, err := requestBodyForApproval(ctx, req)
	if err != nil {
		return types.ApprovalDecision{}, nil, err
	}

	// Retrieve LLM policy from context (set by the proxy handler per-user).
	policy, _ := ctx.Value(ContextKeyLLMPolicy).(*types.LLMPolicy)

	// Check static rules before invoking the judge. Deny takes priority over allow.
	if policy != nil && len(policy.StaticRules) > 0 {
		var hasAllow, hasDeny bool
		for _, rule := range policy.StaticRules {
			if staticRuleMatches(rule, req) {
				if rule.Action == "deny" {
					hasDeny = true
				} else {
					hasAllow = true
				}
			}
		}
		if hasDeny {
			return types.ApprovalDecision{
				Decision:    types.DecisionDeny,
				ApprovedBy:  "llm-static-rule",
				Channel:     "llm",
				Reason:      "matched static deny rule",
				LLMPolicyID: policy.ID,
			}, body, nil
		}
		if hasAllow {
			return types.ApprovalDecision{
				Decision:    types.DecisionAllow,
				ApprovedBy:  "llm-static-rule",
				Channel:     "llm",
				Reason:      "matched static allow rule",
				LLMPolicyID: policy.ID,
			}, body, nil
		}
	}

	if policy == nil || policy.Prompt == "" {
		slog.Debug("LLM mode: no policy in context, using fallback", "request_id", requestID, "fallback", m.fallbackMode)
		return m.llmFallback(ctx, req, requestID, apiInfo, body)
	}

	// Use the original headers/body for LLM evaluation so proxy-internal mutations are not leaked to the judge.
	evalHeaders, _ := ctx.Value(ContextKeyOriginalHeaders).(http.Header)
	if evalHeaders == nil {
		evalHeaders = req.Header
	}
	evalBody, _ := ctx.Value(ContextKeyOriginalBody).([]byte)
	if evalBody == nil {
		evalBody = body
	}

	result, judgeErr := m.judge.Evaluate(ctx, req.Method, req.URL.String(), evalHeaders, string(evalBody), *policy)
	if judgeErr != nil {
		slog.Error("LLM judge error, using fallback", "request_id", requestID, "error", judgeErr, "fallback", m.fallbackMode)
		ad, b, err := m.llmFallback(ctx, req, requestID, apiInfo, body)
		ad.LLMPolicyID = policy.ID
		if result.Model != "" {
			ad.LLMResponse = judgeResultToLLMResponse(result, judgeErr)
		}
		return ad, b, err
	}

	llmResp := judgeResultToLLMResponse(result, nil)
	switch result.Decision {
	case types.DecisionAllow:
		return types.ApprovalDecision{
			Decision:    types.DecisionAllow,
			ApprovedBy:  "llm",
			Channel:     "llm",
			Reason:      result.Reason,
			LLMPolicyID: policy.ID,
			LLMResponse: llmResp,
		}, body, nil
	case types.DecisionDeny:
		return types.ApprovalDecision{
			Decision:    types.DecisionDeny,
			ApprovedBy:  "llm",
			Channel:     "llm",
			Reason:      result.Reason,
			LLMPolicyID: policy.ID,
			LLMResponse: llmResp,
		}, body, nil
	default:
		slog.Warn("LLM judge returned unexpected decision, using fallback", "request_id", requestID, "decision", result.Decision, "fallback", m.fallbackMode)
		ad, b, err := m.llmFallback(ctx, req, requestID, apiInfo, body)
		ad.LLMPolicyID = policy.ID
		ad.LLMResponse = llmResp
		return ad, b, err
	}
}

// requestBodyForApproval returns request bytes for policy checks and for callers
// that need to replay the request upstream. If the proxy already buffered the
// request prefix, use that copy and leave req.Body untouched so large uploads
// can continue streaming after approval.
func requestBodyForApproval(ctx context.Context, req *http.Request) ([]byte, error) {
	if body, ok := ctx.Value(ContextKeyBufferedBody).([]byte); ok {
		return body, nil
	}

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// llmFallback handles the case where the LLM judge is unavailable or returns no valid decision.
func (m *Manager) llmFallback(ctx context.Context, req *http.Request, requestID string, apiInfo *types.APIInfo, body []byte) (types.ApprovalDecision, []byte, error) {
	if m.fallbackMode == "passthrough" {
		slog.Warn("SECURITY EVALUATION SKIPPED: LLM judge unavailable, request auto-approved via passthrough fallback", "request_id", requestID, "method", req.Method, "url", req.URL.String())
		return types.ApprovalDecision{
			Decision:   types.DecisionAllow,
			ApprovedBy: "llm-fallback",
			Channel:    "llm",
			Reason:     "llm judge unavailable, passthrough",
		}, body, nil
	}

	// Default: deny the request when the LLM judge is unavailable.
	return types.ApprovalDecision{
		Decision:   types.DecisionDeny,
		ApprovedBy: "llm-fallback",
		Channel:    "llm",
		Reason:     "llm judge unavailable",
	}, body, nil
}

// UsesLLM reports whether approvals are currently routed through the LLM judge.
func (m *Manager) UsesLLM() bool {
	return m.mode == "llm" && m.judge != nil
}

// UsesPassthrough reports whether approvals are bypassed by configuration.
func (m *Manager) UsesPassthrough() bool {
	return m.mode == "passthrough"
}

// staticRuleMatches reports whether the given rule matches req.
func staticRuleMatches(rule types.StaticRule, req *http.Request) bool {
	method := strings.ToUpper(req.Method)
	if len(rule.Methods) > 0 {
		matched := false
		for _, m := range rule.Methods {
			if strings.ToUpper(m) == method {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return staticURLMatches(req.URL.String(), rule.URLPattern, rule.MatchType)
}

// MatchesStaticRules returns whether the given method+URL matches any static rule,
// and if so, the action of the winning rule ("allow" or "deny"). Deny takes priority.
// Used by the eval runner to mirror production static-rule behaviour.
func MatchesStaticRules(method, rawURL string, rules []types.StaticRule) (matched bool, action string) {
	var hasAllow, hasDeny bool
	for _, rule := range rules {
		if len(rule.Methods) > 0 {
			methodMatched := false
			for _, m := range rule.Methods {
				if strings.EqualFold(m, method) {
					methodMatched = true
					break
				}
			}
			if !methodMatched {
				continue
			}
		}
		if staticURLMatches(rawURL, rule.URLPattern, rule.MatchType) {
			if rule.Action == "deny" {
				hasDeny = true
			} else {
				hasAllow = true
			}
		}
	}
	if hasDeny {
		return true, "deny"
	}
	if hasAllow {
		return true, "allow"
	}
	return false, ""
}

// ValidateStaticRules returns an error if any rule is invalid.
func ValidateStaticRules(rules []types.StaticRule) error {
	for i, rule := range rules {
		if rule.URLPattern == "" {
			return fmt.Errorf("rule %d: url_pattern must not be empty", i)
		}
		switch rule.MatchType {
		case "prefix", "exact", "glob", "":
			// ok — "" defaults to prefix
		default:
			return fmt.Errorf("rule %d: invalid match_type %q: must be prefix, exact, or glob", i, rule.MatchType)
		}
		if rule.MatchType == "glob" {
			if _, err := globToRegexp(rule.URLPattern); err != nil {
				return fmt.Errorf("rule %d: invalid glob pattern %q: %w", i, rule.URLPattern, err)
			}
		}
		switch rule.Action {
		case "allow", "deny", "":
			// ok — "" defaults to allow
		default:
			return fmt.Errorf("rule %d: invalid action %q: must be allow or deny", i, rule.Action)
		}
	}
	return nil
}

// globRegexpCacheMaxSize is the maximum number of compiled regexps to cache.
// In practice the number of distinct glob patterns is small (set by admins),
// so 1024 is generous. When the cap is reached the entire cache is cleared
// — this is simpler than LRU and acceptable because a miss only costs one
// regexp.Compile call.
const globRegexpCacheMaxSize = 1024

// globCache is a bounded cache of compiled regexps keyed by glob pattern.
// Policies are immutable (only forked, never edited) so entries never need
// selective invalidation; the only eviction event is hitting the size cap.
var globCache = struct {
	sync.RWMutex
	m map[string]*regexp.Regexp
}{m: make(map[string]*regexp.Regexp)}

// stripDefaultPort removes the default port from a URL string so that
// "https://example.com:443/path" and "https://example.com/path" are treated
// identically. Only the two well-known defaults are stripped: :443 for https
// and :80 for http. This prevents false-negative rule matches when an HTTP
// client includes the redundant default port in the Host header.
func stripDefaultPort(rawURL string) string {
	// Fast path: no port present at all.
	if !strings.Contains(rawURL, "://") {
		return rawURL
	}
	if strings.HasPrefix(rawURL, "https://") {
		// Remove :443 immediately after the host and before / or end-of-string.
		const prefix = "https://"
		rest := rawURL[len(prefix):]
		if i := strings.Index(rest, ":443"); i >= 0 {
			after := rest[i+4:]
			if after == "" || after[0] == '/' || after[0] == '?' || after[0] == '#' {
				return prefix + rest[:i] + after
			}
		}
	} else if strings.HasPrefix(rawURL, "http://") {
		const prefix = "http://"
		rest := rawURL[len(prefix):]
		if i := strings.Index(rest, ":80"); i >= 0 {
			after := rest[i+3:]
			if after == "" || after[0] == '/' || after[0] == '?' || after[0] == '#' {
				return prefix + rest[:i] + after
			}
		}
	}
	return rawURL
}

func staticURLMatches(urlStr, pattern, matchType string) bool {
	// Decode percent-encoding so that e.g. "/%61dmin" matches a rule for "/admin".
	// Use a single-pass decode only — do NOT decode recursively to prevent
	// double-encoding bypasses (e.g. "%2561" must decode to "%61", not "a").
	decoded, err := url.PathUnescape(urlStr)
	if err != nil {
		decoded = urlStr // fall back to raw string on decode error
	}

	// Normalize away default ports so that e.g. "https://host:443/path"
	// matches a rule written as "https://host/path" and vice-versa.
	decoded = stripDefaultPort(decoded)
	normalizedPattern := stripDefaultPort(pattern)

	switch matchType {
	case "exact":
		return decoded == normalizedPattern
	case "glob":
		// Strip scheme (e.g. "https://") so patterns like "*.example.com/*" work.
		stripped := decoded
		if i := strings.Index(decoded, "://"); i >= 0 {
			stripped = decoded[i+3:]
		}
		re, err := globToRegexp(normalizedPattern)
		if err != nil {
			return false
		}
		return re.MatchString(stripped)
	default: // "prefix" and anything unrecognised
		return strings.HasPrefix(decoded, normalizedPattern)
	}
}

// globToRegexp converts a glob pattern to a compiled regexp, caching the result.
// Two special rules apply:
//   - "*." matches any number of subdomain labels (including none), so "*.example.com"
//     also matches "example.com", "api.example.com", and "sub.api.example.com"
//   - "*" matches any sequence of characters including "/"
func globToRegexp(pattern string) (*regexp.Regexp, error) {
	// Fast path: read lock only.
	globCache.RLock()
	if re, ok := globCache.m[pattern]; ok {
		globCache.RUnlock()
		return re, nil
	}
	globCache.RUnlock()

	// Slow path: compile the regexp, then store under write lock.
	var sb strings.Builder
	sb.WriteString("^")
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '*' && i+1 < len(runes) && runes[i+1] == '.':
			// "*." → optional one-or-more subdomain labels (e.g. "api.", "sub.api.").
			// [^./]+ excludes slashes so query-string injection like
			// evil.com/?x=api.google.com/y cannot match *.google.com/*.
			sb.WriteString(`(([^./]+\.)+)?`)
			i++ // skip the '.'
		case c == '*':
			sb.WriteString(`.*`)
		case strings.ContainsRune(`\.+?()[]{}^$|`, c):
			sb.WriteRune('\\')
			sb.WriteRune(c)
		default:
			sb.WriteRune(c)
		}
	}
	sb.WriteString("$")
	re, err := regexp.Compile(sb.String())
	if err != nil {
		return nil, err
	}

	globCache.Lock()
	// Re-check: another goroutine may have inserted while we compiled.
	if existing, ok := globCache.m[pattern]; ok {
		globCache.Unlock()
		return existing, nil
	}
	// Evict all entries when the cache is full. This is simple, correct,
	// and sufficient because glob patterns change rarely (admin-only).
	if len(globCache.m) >= globRegexpCacheMaxSize {
		globCache.m = make(map[string]*regexp.Regexp)
	}
	globCache.m[pattern] = re
	globCache.Unlock()
	return re, nil
}

// globCacheLen returns the current number of entries in the glob regexp cache.
// Exported for testing only.
func globCacheLen() int {
	globCache.RLock()
	n := len(globCache.m)
	globCache.RUnlock()
	return n
}

// resetGlobCache clears the glob regexp cache. Exported for testing only.
func resetGlobCache() {
	globCache.Lock()
	globCache.m = make(map[string]*regexp.Regexp)
	globCache.Unlock()
}

// judgeResultToLLMResponse converts a JudgeResult to a types.LLMResponse.
func judgeResultToLLMResponse(r judge.JudgeResult, err error) *types.LLMResponse {
	lr := &types.LLMResponse{
		Model:        r.Model,
		DurationMs:   r.DurationMs,
		InputTokens:  r.InputTokens,
		OutputTokens: r.OutputTokens,
		RawOutput:    r.RawOutput,
	}
	if err != nil {
		lr.Result = "error"
		if lr.RawOutput == "" {
			lr.RawOutput = err.Error()
		}
	} else {
		lr.Result = "success"
		lr.Decision = string(r.Decision)
		lr.Reason = r.Reason
	}
	return lr
}
