package approval

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

func newLLMManager(t *testing.T, j *judge.LLMJudge, fallback string) *Manager {
	t.Helper()
	m := NewManager()
	m.SetJudge(j, "llm", fallback)
	return m
}

func allowJudge() *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: `{"decision":"ALLOW","reason":"looks fine"}`}, nil
	}})
}

func denyJudge() *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: `{"decision":"DENY","reason":"not permitted"}`}, nil
	}})
}

func errorJudge(err error) *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{}, err
	}})
}

func countingJudge(decision string, count *int) *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		*count++
		return llm.Response{Text: `{"decision":"` + decision + `","reason":"ok"}`}, nil
	}})
}

func policyCtx(prompt string) context.Context {
	return context.WithValue(context.Background(), ContextKeyLLMPolicy, &types.LLMPolicy{Prompt: prompt})
}

func policyCtxWithID(id, prompt string) context.Context {
	return context.WithValue(context.Background(), ContextKeyLLMPolicy, &types.LLMPolicy{ID: id, Prompt: prompt})
}

func TestLLMJudgeAllow(t *testing.T) {
	manager := newLLMManager(t, allowJudge(), "deny")

	req, _ := http.NewRequest("GET", "https://api.example.com/repos", nil)
	ctx := policyCtx("Allow read-only GitHub access")

	decision, _, err := manager.CheckApproval(ctx, req, "req_llm_allow", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW, got %v", decision.Decision)
	}
	if decision.Channel != "llm" {
		t.Errorf("expected channel=llm, got %q", decision.Channel)
	}
	if decision.ApprovedBy != "llm" {
		t.Errorf("expected approvedBy=llm, got %q", decision.ApprovedBy)
	}
}

func TestLLMJudgeDeny(t *testing.T) {
	manager := newLLMManager(t, denyJudge(), "deny")

	req, _ := http.NewRequest("POST", "https://api.example.com/repos", bytes.NewReader([]byte(`{}`)))
	ctx := policyCtx("Allow read-only GitHub access")

	decision, _, err := manager.CheckApproval(ctx, req, "req_llm_deny", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY, got %v", decision.Decision)
	}
	if decision.Channel != "llm" {
		t.Errorf("expected channel=llm, got %q", decision.Channel)
	}
}

func TestLLMJudgeNoCaching(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	ctx := policyCtx("test policy")
	body := []byte(`{"action":"read"}`)

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", "https://api.example.com/data", bytes.NewReader(body))
		decision, _, err := manager.CheckApproval(ctx, req, "req_nocache", nil)
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i, err)
		}
		if decision.Decision != types.DecisionAllow {
			t.Errorf("call %d: expected ALLOW, got %v", i, decision.Decision)
		}
	}

	// LLM should be called every time (no caching)
	if callCount != 3 {
		t.Errorf("expected judge called 3 times (no caching), got %d", callCount)
	}
}

func TestLLMJudgeFallbackDenyOnError(t *testing.T) {
	manager := newLLMManager(t, errorJudge(errors.New("network error")), "deny")

	req, _ := http.NewRequest("POST", "https://api.example.com/data", bytes.NewReader([]byte(`{}`)))
	ctx := policyCtx("test policy")

	decision, _, err := manager.CheckApproval(ctx, req, "req_fallback_deny", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY on error with fallback=deny, got %v", decision.Decision)
	}
}

func TestLLMJudgeFallbackPassthroughOnError(t *testing.T) {
	manager := newLLMManager(t, errorJudge(errors.New("network error")), "passthrough")

	req, _ := http.NewRequest("POST", "https://api.example.com/data", bytes.NewReader([]byte(`{}`)))
	ctx := policyCtx("test policy")

	decision, _, err := manager.CheckApproval(ctx, req, "req_fallback_passthrough", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW on error with fallback=passthrough, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "llm-fallback" {
		t.Errorf("expected approvedBy=llm-fallback, got %q", decision.ApprovedBy)
	}
}

func TestLLMJudgeNoPromptFallbackDeny(t *testing.T) {
	manager := newLLMManager(t, allowJudge(), "deny")

	req, _ := http.NewRequest("POST", "https://api.example.com/data", bytes.NewReader([]byte(`{}`)))
	// No policy in context

	decision, _, err := manager.CheckApproval(context.Background(), req, "req_no_prompt", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY when no policy and fallback=deny, got %v", decision.Decision)
	}
}

func TestLLMJudgeNoPromptFallbackPassthrough(t *testing.T) {
	manager := newLLMManager(t, allowJudge(), "passthrough")

	req, _ := http.NewRequest("POST", "https://api.example.com/data", bytes.NewReader([]byte(`{}`)))

	decision, _, err := manager.CheckApproval(context.Background(), req, "req_no_prompt_passthrough", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW when no policy and fallback=passthrough, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "llm-fallback" {
		t.Errorf("expected approvedBy=llm-fallback, got %q", decision.ApprovedBy)
	}
}

func TestLLMJudgeGETAlsoEvaluated(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	ctx := policyCtx("Allow GET")
	req, _ := http.NewRequest("GET", "https://api.example.com/repos", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_get_llm", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Channel != "llm" {
		t.Errorf("expected GET to go through LLM judge, got channel=%q", decision.Channel)
	}
	if callCount != 1 {
		t.Errorf("expected judge called once for GET, got %d", callCount)
	}
}

func TestLLMJudgeFallbackDenyOnError_SetsLLMPolicyID(t *testing.T) {
	manager := newLLMManager(t, errorJudge(errors.New("network error")), "deny")

	req, _ := http.NewRequest("POST", "https://api.example.com/data", bytes.NewReader([]byte(`{}`)))
	ctx := policyCtxWithID("llmpol_test123", "test policy")

	decision, _, err := manager.CheckApproval(ctx, req, "req_fallback_policy_id", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.LLMPolicyID != "llmpol_test123" {
		t.Errorf("LLMPolicyID: want %q, got %q", "llmpol_test123", decision.LLMPolicyID)
	}
}

func TestLLMJudgeFallbackPassthroughOnError_SetsLLMPolicyID(t *testing.T) {
	manager := newLLMManager(t, errorJudge(errors.New("network error")), "passthrough")

	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	ctx := policyCtxWithID("llmpol_test456", "test policy")

	decision, _, err := manager.CheckApproval(ctx, req, "req_fallback_passthrough_policy_id", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.LLMPolicyID != "llmpol_test456" {
		t.Errorf("LLMPolicyID: want %q, got %q", "llmpol_test456", decision.LLMPolicyID)
	}
}

// ---- Passthrough rule tests ----

func policyCtxWithRules(id, prompt string, rules []types.StaticRule) context.Context {
	return context.WithValue(context.Background(), ContextKeyLLMPolicy, &types.LLMPolicy{
		ID:          id,
		Prompt:      prompt,
		StaticRules: rules,
	})
}

func TestStaticRule_AllowMatchingRequestSkipsJudge(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	rules := []types.StaticRule{{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "allow"}}
	ctx := policyCtxWithRules("llmpol_pt1", "test", rules)
	req, _ := http.NewRequest("GET", "https://api.example.com/repos", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_pt_skip", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW, got %v", decision.Decision)
	}
	if decision.Channel != "llm" {
		t.Errorf("expected channel=llm, got %q", decision.Channel)
	}
	if decision.ApprovedBy != "llm-static-rule" {
		t.Errorf("expected approvedBy=llm-static-rule, got %q", decision.ApprovedBy)
	}
	if decision.LLMPolicyID != "llmpol_pt1" {
		t.Errorf("LLMPolicyID: want %q, got %q", "llmpol_pt1", decision.LLMPolicyID)
	}
	if callCount != 0 {
		t.Errorf("expected judge not called, got %d calls", callCount)
	}
}

func TestStaticRule_DenyMatchingRequestBlocksWithoutJudge(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	rules := []types.StaticRule{{Methods: []string{"DELETE"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "deny"}}
	ctx := policyCtxWithRules("llmpol_deny1", "test", rules)
	req, _ := http.NewRequest("DELETE", "https://api.example.com/repos/1", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_deny_skip", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "llm-static-rule" {
		t.Errorf("expected approvedBy=llm-static-rule, got %q", decision.ApprovedBy)
	}
	if callCount != 0 {
		t.Errorf("expected judge not called, got %d calls", callCount)
	}
}

func TestStaticRule_DenyWinsOverAllow(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	// Both rules match — deny must win
	rules := []types.StaticRule{
		{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "allow"},
		{Methods: []string{"GET"}, URLPattern: "https://api.example.com/danger", MatchType: "prefix", Action: "deny"},
	}
	ctx := policyCtxWithRules("llmpol_deny2", "test", rules)
	req, _ := http.NewRequest("GET", "https://api.example.com/danger/sensitive", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_deny_wins", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("expected DENY (deny takes priority), got %v", decision.Decision)
	}
	if callCount != 0 {
		t.Errorf("expected judge not called, got %d calls", callCount)
	}
}

func TestStaticRule_NonMatchingMethodGoesToJudge(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	// Rule only matches GET; request is POST
	rules := []types.StaticRule{{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix"}}
	ctx := policyCtxWithRules("llmpol_pt2", "test", rules)
	req, _ := http.NewRequest("POST", "https://api.example.com/repos", bytes.NewReader([]byte(`{}`)))

	decision, _, err := manager.CheckApproval(ctx, req, "req_pt_method_miss", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Channel != "llm" {
		t.Errorf("expected channel=llm (judge ran), got %q", decision.Channel)
	}
	if callCount != 1 {
		t.Errorf("expected judge called once, got %d", callCount)
	}
}

func TestStaticRule_NonMatchingURLGoesToJudge(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	rules := []types.StaticRule{{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix"}}
	ctx := policyCtxWithRules("llmpol_pt3", "test", rules)
	req, _ := http.NewRequest("GET", "https://other.example.com/repos", nil)

	decision, _, err := manager.CheckApproval(ctx, req, "req_pt_url_miss", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Channel != "llm" {
		t.Errorf("expected channel=llm (judge ran), got %q", decision.Channel)
	}
	if callCount != 1 {
		t.Errorf("expected judge called once, got %d", callCount)
	}
}

func TestStaticRule_EmptyMethodsMatchesAll(t *testing.T) {
	callCount := 0
	manager := newLLMManager(t, countingJudge("ALLOW", &callCount), "deny")

	rules := []types.StaticRule{{Methods: []string{}, URLPattern: "https://api.example.com/", MatchType: "prefix"}}
	ctx := policyCtxWithRules("llmpol_pt4", "test", rules)

	for _, method := range []string{"GET", "POST", "DELETE", "PATCH"} {
		req, _ := http.NewRequest(method, "https://api.example.com/data", bytes.NewReader([]byte(`{}`)))
		decision, _, err := manager.CheckApproval(ctx, req, "req_pt_allmethods_"+method, nil)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", method, err)
		}
		if decision.Channel != "llm" {
			t.Errorf("%s: expected channel=llm, got %q", method, decision.Channel)
		}
		if decision.ApprovedBy != "llm-static-rule" {
			t.Errorf("%s: expected approvedBy=llm-static-rule, got %q", method, decision.ApprovedBy)
		}
	}
	if callCount != 0 {
		t.Errorf("expected judge never called, got %d calls", callCount)
	}
}

func TestValidateStaticRules(t *testing.T) {
	cases := []struct {
		name    string
		rules   []types.StaticRule
		wantErr bool
	}{
		{
			name:    "valid allow prefix rule",
			rules:   []types.StaticRule{{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "allow"}},
			wantErr: false,
		},
		{
			name:    "valid deny rule",
			rules:   []types.StaticRule{{URLPattern: "https://dangerous.example.com/", MatchType: "prefix", Action: "deny"}},
			wantErr: false,
		},
		{
			name:    "valid glob rule",
			rules:   []types.StaticRule{{URLPattern: "*.example.com/*", MatchType: "glob"}},
			wantErr: false,
		},
		{
			name:    "empty match_type defaults to prefix — valid",
			rules:   []types.StaticRule{{URLPattern: "https://api.example.com/"}},
			wantErr: false,
		},
		{
			name:    "empty action defaults to allow — valid",
			rules:   []types.StaticRule{{URLPattern: "https://api.example.com/", Action: ""}},
			wantErr: false,
		},
		{
			name:    "empty url_pattern rejected",
			rules:   []types.StaticRule{{URLPattern: "", MatchType: "prefix"}},
			wantErr: true,
		},
		{
			name:    "unknown match_type rejected",
			rules:   []types.StaticRule{{URLPattern: "https://api.example.com/", MatchType: "prefixx"}},
			wantErr: true,
		},
		{
			name:    "unknown action rejected",
			rules:   []types.StaticRule{{URLPattern: "https://api.example.com/", Action: "maybe"}},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStaticRules(tc.rules)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestStaticURLMatches(t *testing.T) {
	cases := []struct {
		urlStr    string
		pattern   string
		matchType string
		want      bool
	}{
		// prefix (default)
		{"https://api.example.com/repos", "https://api.example.com/", "prefix", true},
		{"https://api.example.com/repos", "https://other.com/", "prefix", false},
		{"https://api.example.com/repos", "https://api.example.com/repos", "", true}, // exact prefix
		// exact
		{"https://api.example.com/repos", "https://api.example.com/repos", "exact", true},
		{"https://api.example.com/repos/123", "https://api.example.com/repos", "exact", false},
		// glob — scheme is stripped; * matches any chars including /
		{"https://api.example.com/repos", "api.example.com/repos", "glob", true},
		{"https://api.example.com/repos/123", "api.example.com/repos/*", "glob", true},
		{"https://api.example.com/repos/123/comments", "api.example.com/repos/*", "glob", true}, // * crosses /
		{"https://other.example.com/repos", "api.example.com/repos", "glob", false},
		// wildcard subdomain: "*." matches any number of subdomain labels (including none)
		{"https://api.google.com/something", "*.google.com/*", "glob", true},
		{"https://www.google.com/search", "*.google.com/*", "glob", true},
		{"https://api.google.com/v1/users", "*.google.com/*", "glob", true},          // * crosses /
		{"https://google.com/search", "*.google.com/*", "glob", true},                // bare domain — subdomain is optional
		{"https://sub.api.google.com/search", "*.google.com/*", "glob", true},        // multi-level subdomain
		{"https://evil.notgoogle.com/search",                    "*.google.com/*", "glob", false}, // suffix mismatch
		// injection attacks: domain embedded in query string or path must not match
		{"https://evil.com/?foo=https://api.google.com/sensitive", "*.google.com/*", "glob", false},
		{"https://evil.com/redirect/api.google.com/sensitive",     "*.google.com/*", "glob", false},
		// mid-pattern wildcard
		{"https://api.example.com/repos/123/comments",       "api.example.com/repos/*/comments", "glob", true},
		{"https://api.example.com/repos/123/extra/comments", "api.example.com/repos/*/comments", "glob", true},  // * crosses /
		{"https://api.example.com/repos/comments",           "api.example.com/repos/*/comments", "glob", false}, // empty segment — * requires at least one char
		{"https://api.example.com/repos/123/comments/extra", "api.example.com/repos/*/comments", "glob", false}, // trailing extra
		// glob with scheme in the pattern — scheme stripped symmetrically so it still matches
		{"https://api.github.com/repos/owner/repo/readme", "https://api.github.com/repos/*/*/readme", "glob", true},
		{"https://api.github.com/repos/owner/repo/readme", "http://api.github.com/repos/*/*/readme", "glob", true}, // scheme in pattern is ignored
		// default port normalisation — :443 for https, :80 for http
		{"https://brex.okta.com:443/.well-known/openid-configuration", "https://brex.okta.com/", "prefix", true},
		{"https://brex.okta.com/.well-known/openid-configuration", "https://brex.okta.com:443/", "prefix", true},
		{"https://brex.okta.com:443/path", "https://brex.okta.com:443/path", "exact", true},
		{"https://brex.okta.com:443/path", "https://brex.okta.com/path", "exact", true},
		{"https://brex.okta.com/path", "https://brex.okta.com:443/path", "exact", true},
		{"http://example.com:80/foo", "http://example.com/", "prefix", true},
		{"http://example.com/foo", "http://example.com:80/", "prefix", true},
		// non-default ports must NOT be stripped
		{"https://example.com:8443/foo", "https://example.com/", "prefix", false},
		{"http://example.com:8080/foo", "http://example.com/", "prefix", false},
		{"https://example.com:443/foo", "*.example.com/*", "glob", true},
		{"http://example.com:80/foo", "example.com/*", "glob", true},
		// host matching is case-insensitive; scheme and host fold, path does not
		{"https://EXAMPLE.COM/repos", "https://example.com/", "prefix", true},
		{"HTTPS://Example.Com/repos", "https://example.com/repos", "exact", true},
		{"https://API.Example.com/x", "*.example.com/*", "glob", true},
		{"https://example.com/Repos", "https://example.com/repos", "exact", false}, // path case is preserved
	}

	for _, tc := range cases {
		got := staticURLMatches(tc.urlStr, tc.pattern, tc.matchType)
		if got != tc.want {
			t.Errorf("staticURLMatches(%q, %q, %q) = %v, want %v",
				tc.urlStr, tc.pattern, tc.matchType, got, tc.want)
		}
	}
}
