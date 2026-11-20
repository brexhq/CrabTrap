package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

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

// DecisionObserver is notified about the final approval decision and the
// end-to-end pipeline latency. Implementations must be safe for concurrent
// use. The hook is optional: a nil observer disables recording. Kept as a
// small interface to avoid a dependency on internal/metrics from the approval
// package.
//
// Fires only on successful (non-error) returns from CheckApproval; malformed
// requests that error out before a decision is reached are excluded from both
// counter and histogram.
type DecisionObserver interface {
	OnApprovalDecision(outcome, mode string)
	OnApprovalLatency(mode, outcome string, d time.Duration)
}

// Manager orchestrates the approval decision flow
type Manager struct {
	judge        judge.Evaluator // nil if LLM mode disabled
	mode         string          // "llm" | "passthrough"
	fallbackMode string          // "deny" | "passthrough"

	observer DecisionObserver

	// decisionCache reuses a judge decision for identical requests. Configured
	// via SetDecisionCache; disabled (nil) by default.
	decisionCache *decisionCache

	// inflight serializes concurrent misses for the same fingerprint so a
	// burst of identical requests triggers one judge call.
	inflightMu sync.Mutex
	inflight   map[string]chan struct{}
}

// NewManager creates a new approval manager.
func NewManager() *Manager {
	return &Manager{
		mode: "llm",
	}
}

// SetDecisionCache enables bounded reuse of LLM judge decisions. ttl<=0 or
// maxUses<=0 disables caching. Only terminal judge decisions are cached —
// fallback/deny-on-error results and errors are never stored.
func (m *Manager) SetDecisionCache(ttl time.Duration, maxUses int) {
	if ttl <= 0 || maxUses <= 0 {
		m.decisionCache = nil
		return
	}
	m.decisionCache = &decisionCache{
		ttl:     ttl,
		maxUses: maxUses,
		entries: make(map[string]cachedDecision),
	}
	m.inflight = make(map[string]chan struct{})
}

// decisionCache is a bounded, concurrency-safe cache keyed by a deterministic
// fingerprint of the judged request. A global monotonically increasing counter
// gives cheap FIFO eviction without an LRU list.
type decisionCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxUses int
	entries map[string]cachedDecision
	seq     int64
}

type cachedDecision struct {
	decision  types.ApprovalDecision
	expiresAt time.Time
	uses      int
	order     int64
}

// get returns a still-valid cached decision and consumes one use. Entries that
// expired or exhausted are dropped.
func (c *decisionCache) get(key string, now time.Time) (types.ApprovalDecision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return types.ApprovalDecision{}, false
	}
	if now.After(e.expiresAt) || e.uses >= c.maxUses {
		delete(c.entries, key)
		return types.ApprovalDecision{}, false
	}
	e.uses++
	c.entries[key] = e
	return e.decision, true
}

// put stores a fresh decision, evicting the oldest entry when the fixed size
// bound (1024) is exceeded. A miss only costs a new judge call, so simple FIFO
// eviction is sufficient.
func (c *decisionCache) put(key string, d types.ApprovalDecision, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	c.entries[key] = cachedDecision{decision: d, expiresAt: now.Add(c.ttl), order: c.seq}
	const maxEntries = 1024
	if len(c.entries) > maxEntries {
		var oldestKey string
		var oldestSeq int64 = -1
		for k, e := range c.entries {
			if oldestSeq < 0 || e.order < oldestSeq {
				oldestKey, oldestSeq = k, e.order
			}
		}
		delete(c.entries, oldestKey)
	}
}

// SetMode configures the approval mode used by CheckApproval.
func (m *Manager) SetMode(mode string) {
	if mode == "" {
		mode = "llm"
	}
	m.mode = mode
}

// SetJudge configures the request evaluator (LLM judge, Jev cascade evaluator, etc.)
// and switches the manager to the given mode. A nil pointer (e.g. a nil
// *judge.LLMJudge) is treated as no judge, so requests use the fallback
// instead of panicking.
func (m *Manager) SetJudge(j judge.Evaluator, mode, fallbackMode string) {
	if j != nil {
		if v := reflect.ValueOf(j); v.Kind() == reflect.Pointer && v.IsNil() {
			j = nil
		}
	}
	m.judge = j
	m.SetMode(mode)
	m.fallbackMode = fallbackMode
}

// SetObserver attaches an optional observer that receives each decision. Must
// be called before the manager starts handling traffic; not intended for
// concurrent reconfiguration.
func (m *Manager) SetObserver(obs DecisionObserver) {
	m.observer = obs
}

// CheckApproval checks if a request should be allowed.
// In "llm" mode every request (including GET) is evaluated by the LLM judge; no caching.
// In "passthrough" mode every request is auto-approved.
func (m *Manager) CheckApproval(ctx context.Context, req *http.Request, requestID string, apiInfo *types.APIInfo) (types.ApprovalDecision, []byte, error) {
	start := time.Now()
	decision, body, err := m.checkApproval(ctx, req, requestID, apiInfo)
	if m.observer != nil && err == nil {
		outcome := string(decision.Decision)
		m.observer.OnApprovalDecision(outcome, m.mode)
		m.observer.OnApprovalLatency(m.mode, outcome, time.Since(start))
	}
	return decision, body, err
}

func (m *Manager) checkApproval(ctx context.Context, req *http.Request, requestID string, apiInfo *types.APIInfo) (types.ApprovalDecision, []byte, error) {
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

	// Decision cache: reuse a terminal judge decision for an identical request.
	// The fingerprint includes identity-bearing headers and the policy so two
	// different users or policies can never share a cached verdict. Static-rule
	// and fallback decisions are intentionally never cached.
	var cacheKey string
	if m.decisionCache != nil {
		cacheKey = decisionFingerprint(req.Method, req.URL.String(), evalHeaders, evalBody, policy)
		if cached, ok := m.decisionCache.get(cacheKey, time.Now()); ok {
			slog.Debug("LLM decision cache hit", "request_id", requestID, "fingerprint", cacheKey[:12])
			return cacheHitDecision(cached), body, nil
		}
		// Single-flight: if another goroutine is judging this fingerprint,
		// wait for it and re-read the cache instead of judging in parallel.
		m.inflightMu.Lock()
		if ch, ok := m.inflight[cacheKey]; ok {
			m.inflightMu.Unlock()
			select {
			case <-ch:
			case <-ctx.Done():
				return types.ApprovalDecision{}, nil, ctx.Err()
			}
			if cached, ok := m.decisionCache.get(cacheKey, time.Now()); ok {
				return cacheHitDecision(cached), body, nil
			}
		} else {
			ch := make(chan struct{})
			m.inflight[cacheKey] = ch
			m.inflightMu.Unlock()
			defer func() {
				m.inflightMu.Lock()
				delete(m.inflight, cacheKey)
				close(ch)
				m.inflightMu.Unlock()
			}()
		}
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
	approvedBy := result.DecidedBy
	if approvedBy == "" {
		approvedBy = "llm"
	}
	var decision types.ApprovalDecision
	switch result.Decision {
	case types.DecisionAllow:
		decision = types.ApprovalDecision{
			Decision:    types.DecisionAllow,
			ApprovedBy:  approvedBy,
			Channel:     "llm",
			Reason:      result.Reason,
			LLMPolicyID: policy.ID,
			LLMResponse: llmResp,
		}
	case types.DecisionDeny:
		decision = types.ApprovalDecision{
			Decision:    types.DecisionDeny,
			ApprovedBy:  approvedBy,
			Channel:     "llm",
			Reason:      result.Reason,
			LLMPolicyID: policy.ID,
			LLMResponse: llmResp,
		}
	default:
		slog.Warn("LLM judge returned unexpected decision, using fallback", "request_id", requestID, "decision", result.Decision, "fallback", m.fallbackMode)
		ad, b, err := m.llmFallback(ctx, req, requestID, apiInfo, body)
		ad.LLMPolicyID = policy.ID
		ad.LLMResponse = llmResp
		return ad, b, err
	}

	if cacheKey != "" {
		m.decisionCache.put(cacheKey, decision, time.Now())
	}
	return decision, body, nil
}

// decisionFingerprint builds a collision-resistant key over every input the
// judge actually sees: method, URL, identity-bearing headers, body and the
// whole policy. Hashing the full policy (not just ID+prompt) means edits to
// static rules, provider, model, status or metadata invalidate stale verdicts.
// Headers are JSON-encoded (sorted keys) so map order cannot change the key.
func decisionFingerprint(method, rawURL string, headers http.Header, body []byte, policy *types.LLMPolicy) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(rawURL))
	h.Write([]byte{0})

	// Mirror the judge's header-of-interest set as JSON: names, value lists and
	// their boundaries stay unambiguous, and encoding/json sorts map keys so
	// output does not depend on map iteration order.
	headerMap := make(map[string][]string, len(headers))
	for name := range headers {
		name = strings.ToLower(name)
		values := headers.Values(name)
		if len(values) > 0 {
			headerMap[name] = values
		}
	}
	if b, err := json.Marshal(headerMap); err == nil {
		h.Write(b)
	}
	h.Write([]byte{0})

	bodyHash := sha256.Sum256(body)
	h.Write(bodyHash[:])
	h.Write([]byte{0})
	if policy != nil {
		// json.Marshal on a struct is deterministic (field order is fixed), so
		// the key is stable across calls. It fails only on unsupported types,
		// which LLMPolicy has none of.
		if b, err := json.Marshal(policy); err == nil {
			h.Write(b)
			h.Write([]byte{0})
		}
		h.Write([]byte(policy.ID))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cacheHitDecision marks a cached verdict as served from the decision cache so
// the audit trail does not credit the original approver. The cached value
// itself is never mutated.
func cacheHitDecision(d types.ApprovalDecision) types.ApprovalDecision {
	d.ApprovedBy = "cache"
	d.Channel = "cache"
	return d
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
			// Strip scheme before validation and regexp compilation so the cached regex
			// has the same inAuthority semantics as the match-time path. Without this,
			// the "://" in the pattern would prematurely end the authority during
			// compile-check, caching a wrong-semantics regex.
			pattern := rule.URLPattern
			// Strip scheme if present
			if idx := strings.Index(pattern, "://"); idx >= 0 {
				pattern = pattern[idx+3:]
			}

			// Compile-check the pattern (operates on scheme-stripped form for correct semantics)
			if _, err := globToRegexp(pattern); err != nil {
				return fmt.Errorf("rule %d: invalid glob pattern %q: %w", i, rule.URLPattern, err)
			}

			// Reject glob patterns with unsafe wildcards in the authority portion.
			// Find the authority portion (before first '/', '?', or '#')
			authorityEnd := len(pattern)
			for pos, c := range pattern {
				if c == '/' || c == '?' || c == '#' {
					authorityEnd = pos
					break
				}
			}
			authority := pattern[:authorityEnd]

			// Check for wildcards in authority:
			// - "*." at position 0 is OK (multi-label subdomain form, e.g. "*.github.com/*")
			// - "*." at any other position is UNSAFE (e.g. "api.*.com/*" matches "api.github.com.evil.com")
			// - Bare "*" anywhere in authority is UNSAFE (e.g. "api.github.com*/*")
			for pos := 0; pos < len(authority); pos++ {
				if authority[pos] == '*' {
					if pos+1 < len(authority) && authority[pos+1] == '.' {
						// This is a "*." form. Only safe at position 0.
						if pos == 0 {
							continue // leading "*." is the safe subdomain wildcard
						}
						return fmt.Errorf("rule %d: glob pattern %q has '*.' at position %d in the authority; '*.' is only safe at the start (use '*.domain.com/*', not 'api.*.com/*')", i, rule.URLPattern, pos)
					}
					// Bare "*" (not followed by ".") in authority
					return fmt.Errorf("rule %d: glob pattern %q has a bare '*' at position %d in the authority that can cross host boundaries; use '*.domain.com/*' for subdomains or 'domain.com/*' for paths", i, rule.URLPattern, pos)
				}
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

// lowerAuthority lowercases the scheme and host of a URL or URL-like pattern
// while leaving the path, query, and fragment untouched. Host names and
// schemes are case-insensitive, but paths and query strings are not, so only
// the authority may be folded. Any userinfo before "@" is preserved as-is.
// A bare pattern with no scheme (e.g. "example.com/*") is treated as
// starting with its authority.
func lowerAuthority(s string) string {
	schemeEnd := 0
	if i := strings.Index(s, "://"); i >= 0 {
		schemeEnd = i + len("://")
	}
	rest := s[schemeEnd:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	host := authority
	userinfo := ""
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo = authority[:at+1]
		host = authority[at+1:]
	}
	return strings.ToLower(s[:schemeEnd]) + userinfo + strings.ToLower(host) + rest[end:]
}

func staticURLMatches(urlStr, pattern, matchType string) bool {
	// Decode percent-encoding so that e.g. "/%61dmin" matches a rule for "/admin".
	// Use a single-pass decode only — do NOT decode recursively to prevent
	// double-encoding bypasses (e.g. "%2561" must decode to "%61", not "a").
	decoded, err := url.PathUnescape(urlStr)
	if err != nil {
		decoded = urlStr // fall back to raw string on decode error
	}

	// Host names are case-insensitive (RFC 4343), so fold the scheme and host
	// of both the URL and the pattern to lower case before comparing. Without
	// this a rule for "api.example.com" does not match a request to
	// "API.Example.com" even though both reach the same server. Only the
	// authority is folded; the path and query are left as-is because those
	// are case-sensitive.
	//
	// This runs before stripDefaultPort because that function matches the
	// scheme case-sensitively, so an uppercase scheme would otherwise keep
	// its redundant default port.
	decoded = lowerAuthority(decoded)
	normalizedPattern := lowerAuthority(pattern)

	// Normalize away default ports so that e.g. "https://host:443/path"
	// matches a rule written as "https://host/path" and vice-versa.
	decoded = stripDefaultPort(decoded)
	normalizedPattern = stripDefaultPort(normalizedPattern)

	switch matchType {
	case "exact":
		return decoded == normalizedPattern
	case "glob":
		// Strip scheme (e.g. "https://") from both the URL and the pattern so
		// that patterns authored with or without a scheme behave identically.
		// The URL string reconstructed by the proxy always carries a scheme;
		// user-authored patterns may or may not.
		stripped := decoded
		if i := strings.Index(decoded, "://"); i >= 0 {
			stripped = decoded[i+3:]
		}
		patternForGlob := normalizedPattern
		if i := strings.Index(normalizedPattern, "://"); i >= 0 {
			patternForGlob = normalizedPattern[i+3:]
		}
		re, err := globToRegexp(patternForGlob)
		if err != nil {
			return false
		}
		return re.MatchString(stripped)
	default: // "prefix" and anything unrecognised
		if !strings.HasPrefix(decoded, normalizedPattern) {
			return false
		}
		// Require the match to end on an authority/path boundary so a rule for
		// "https://api.github.com" cannot match "https://api.github.com.evil.example"
		// or "https://api.github.com@evil.example". This prevents host-boundary bypass
		// where a static allow short-circuits the LLM judge.
		//
		// If the pattern already ends with an authority terminator ('/', '?', '#'),
		// then we're already past the authority boundary and any remainder is valid.
		// Otherwise, the remainder must be empty or start with an authority terminator.
		if len(normalizedPattern) > 0 {
			lastChar := normalizedPattern[len(normalizedPattern)-1]
			if lastChar == '/' || lastChar == '?' || lastChar == '#' {
				return true // pattern already past authority boundary
			}
		}
		rem := decoded[len(normalizedPattern):]
		return rem == "" || rem[0] == '/' || rem[0] == '?' || rem[0] == '#'
	}
}

// globToRegexp converts a glob pattern to a compiled regexp, caching the result.
// Three special rules apply:
//   - "*." matches any number of subdomain labels (including none), so "*.example.com"
//     also matches "example.com", "api.example.com", and "sub.api.example.com"
//   - "*" in the authority (before the first "/") is boundary-safe: it compiles to [^./:]*
//     so that "api.github.com*" cannot match "api.github.com.evil.example"
//   - "*" in the path/query (after the first "/") matches any sequence including "/"
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
	inAuthority := true      // tracks whether we're in the authority (before first '/')
	atAuthorityStart := true // true only for the very first character(s) of authority
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == '/' || c == '?' || c == '#':
			// These characters mark the end of the authority portion.
			// Everything after is path, query, or fragment.
			inAuthority = false
			atAuthorityStart = false
			if strings.ContainsRune(`?`, c) {
				// '?' is a regex metacharacter, escape it
				sb.WriteRune('\\')
			}
			sb.WriteRune(c)
		case c == '*' && i+1 < len(runes) && runes[i+1] == '.':
			// "*." is the multi-label subdomain wildcard, but ONLY when at the START
			// of the authority (position 0). At position 0, "*.example.com" safely
			// matches "api.example.com" and "sub.api.example.com" but not
			// "api.example.com.evil.com". At any other position, "*." would allow
			// "api.*.com" to match "api.github.com.evil.com" if an attacker owns
			// evil.com and registers that subdomain.
			if inAuthority && atAuthorityStart {
				// Leading "*." → optional one-or-more subdomain labels.
				// [^./]+ excludes slashes so query-string injection like
				// evil.com/?x=api.google.com/y cannot match *.google.com/*.
				sb.WriteString(`(([^./]+\.)+)?`)
				i++ // skip the '.'
				// After the optional subdomain(s), we're positioned at the start of
				// the base domain. We're no longer at the authority start for purposes
				// of allowing another "*.".
				atAuthorityStart = false
			} else if inAuthority {
				// Mid-authority "*." is UNSAFE and should never match (validation rejects
				// it, but for defense-in-depth we compile it to match nothing useful).
				// Patterns like "api.*.com" or "*.*.com" can be abused to match across
				// domain boundaries via backtracking. Compile as just "\." (literal dot,
				// discarding the *), which makes "api.*.com" match "api..com" (double
				// dot), effectively matching nothing.
				sb.WriteString(`\.`)
				i++ // skip the '.'
				atAuthorityStart = false
			} else {
				// Path-position "*.": * matches anything, . is literal.
				sb.WriteString(`.*\.`)
				i++ // skip the '.'
			}
		case c == '*':
			if inAuthority {
				// In authority: bare * must not cross domain boundaries. Use [^./:]*
				// to exclude dots (domain separators), slashes (authority terminator),
				// and colons (port delimiter). This prevents "api.github.com*" from
				// matching "api.github.com.evil.example".
				sb.WriteString(`[^./:]*`)
				atAuthorityStart = false
			} else {
				// In path/query/fragment: * can match any sequence including '/'.
				sb.WriteString(`.*`)
			}
		case strings.ContainsRune(`\.+?()[]{}^$|`, c):
			sb.WriteRune('\\')
			sb.WriteRune(c)
			atAuthorityStart = false
		default:
			sb.WriteRune(c)
			atAuthorityStart = false
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
