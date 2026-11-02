package approval

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

func TestCheckApprovalPassthroughMode(t *testing.T) {
	manager := NewManager()
	manager.SetMode("passthrough")

	req, err := http.NewRequest("POST", "https://api.example.com/users", bytes.NewReader([]byte(`{"name":"John"}`)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	decision, body, err := manager.CheckApproval(context.Background(), req, "req_passthrough", nil)
	if err != nil {
		t.Fatalf("CheckApproval failed: %v", err)
	}
	if decision.Decision != types.DecisionAllow {
		t.Fatalf("Expected allow, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "passthrough" {
		t.Fatalf("Expected approved_by passthrough, got %q", decision.ApprovedBy)
	}
	if decision.Channel != "passthrough" {
		t.Fatalf("Expected channel passthrough, got %q", decision.Channel)
	}
	if body != nil {
		t.Fatal("Expected nil body in passthrough mode")
	}
}

func TestCheckApprovalNoJudgeDenies(t *testing.T) {
	manager := NewManager()
	manager.SetMode("llm") // explicitly set llm mode to test deny path

	req, err := http.NewRequest("POST", "https://api.example.com/users", bytes.NewReader([]byte(`{"name":"John"}`)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	decision, _, err := manager.CheckApproval(context.Background(), req, "req_no_judge", nil)
	if err != nil {
		t.Fatalf("CheckApproval failed: %v", err)
	}
	if decision.Decision != types.DecisionDeny {
		t.Errorf("Expected deny when no judge configured, got %v", decision.Decision)
	}
	if decision.ApprovedBy != "system" {
		t.Errorf("Expected approved_by system, got %q", decision.ApprovedBy)
	}
	if decision.Reason != "llm judge not configured" {
		t.Errorf("Expected reason 'llm judge not configured', got %q", decision.Reason)
	}
}

func TestSetJudgeTypedNilFallsBackToNotConfigured(t *testing.T) {
	for name, j := range map[string]judge.Evaluator{
		"nil LLMJudge": (*judge.LLMJudge)(nil),
		"nil cascade":  (*judge.JevCascadeEvaluator)(nil),
		"untyped nil":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			manager := NewManager()
			manager.SetJudge(j, "llm", "passthrough")
			if manager.UsesLLM() {
				t.Fatal("UsesLLM()=true for a nil judge")
			}

			req, _ := http.NewRequest("GET", "https://api.example.com/repos", nil)
			decision, _, err := manager.CheckApproval(context.Background(), req, "req_typed_nil", nil)
			if err != nil {
				t.Fatalf("CheckApproval failed: %v", err)
			}
			if decision.Decision != types.DecisionDeny || decision.Reason != "llm judge not configured" {
				t.Fatalf("decision=%v reason=%q, want deny 'llm judge not configured'", decision.Decision, decision.Reason)
			}
		})
	}
}

func TestCheckApprovalLLMAllow(t *testing.T) {
	j := judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: `{"decision":"ALLOW","reason":"looks fine"}`}, nil
	}})
	manager := NewManager()
	manager.SetJudge(j, "llm", "deny")

	req, _ := http.NewRequest("GET", "https://api.example.com/repos", nil)
	ctx := context.WithValue(context.Background(), ContextKeyLLMPolicy, &types.LLMPolicy{Prompt: "Allow read-only GitHub access"})

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

func TestSetModeDefaultsToLLM(t *testing.T) {
	manager := NewManager()
	manager.SetMode("")

	if !manager.UsesLLM() {
		// UsesLLM requires judge != nil, so just check the mode field indirectly
		// by verifying it's not passthrough
		if manager.UsesPassthrough() {
			t.Error("Expected default mode to be llm, but got passthrough")
		}
	}
}

func TestStaticURLMatchesPercentEncoding(t *testing.T) {
	t.Run("prefix match decodes percent-encoded path", func(t *testing.T) {
		// /%61dmin -> /admin after decoding
		if !staticURLMatches("https://example.com/%61dmin", "https://example.com/admin", "prefix") {
			t.Error("expected /%61dmin to match prefix /admin after percent-decoding")
		}
	})

	t.Run("exact match decodes percent-encoded path", func(t *testing.T) {
		if !staticURLMatches("https://example.com/%61dmin", "https://example.com/admin", "exact") {
			t.Error("expected /%61dmin to match exact /admin after percent-decoding")
		}
	})

	t.Run("glob match decodes percent-encoded path", func(t *testing.T) {
		if !staticURLMatches("https://example.com/%61dmin/settings", "example.com/admin/*", "glob") {
			t.Error("expected /%61dmin/settings to match glob /admin/* after percent-decoding")
		}
	})

	t.Run("double encoding is NOT fully decoded", func(t *testing.T) {
		// %2561 should decode to %61 (one pass), NOT to "a" (two passes).
		// So "/%2561dmin" -> "/%61dmin" which should NOT match "/admin".
		if staticURLMatches("https://example.com/%2561dmin", "https://example.com/admin", "prefix") {
			t.Error("expected /%2561dmin to NOT match /admin (double-encoding must not be fully decoded)")
		}
		if staticURLMatches("https://example.com/%2561dmin", "https://example.com/admin", "exact") {
			t.Error("expected /%2561dmin to NOT match exact /admin (double-encoding must not be fully decoded)")
		}
	})

	t.Run("staticRuleMatches uses decoded URL", func(t *testing.T) {
		// Build a request with a percent-encoded URL; verify staticRuleMatches catches it.
		reqURL, _ := url.Parse("https://example.com/%61dmin")
		req := &http.Request{Method: "GET", URL: reqURL}
		rule := types.StaticRule{
			URLPattern: "https://example.com/admin",
			MatchType:  "prefix",
			Action:     "deny",
		}
		if !staticRuleMatches(rule, req) {
			t.Error("expected staticRuleMatches to match /%61dmin against /admin deny rule")
		}
	})

	t.Run("MatchesStaticRules catches encoded URL", func(t *testing.T) {
		rules := []types.StaticRule{
			{URLPattern: "https://example.com/admin", MatchType: "prefix", Action: "deny"},
		}
		matched, action := MatchesStaticRules("GET", "https://example.com/%61dmin", rules)
		if !matched || action != "deny" {
			t.Errorf("expected MatchesStaticRules to deny /%s61dmin, got matched=%v action=%q", "%", matched, action)
		}
	})
}

func TestStaticURLMatchesDefaultPortNormalisation(t *testing.T) {
	t.Run("staticRuleMatches normalises :443 in request URL", func(t *testing.T) {
		// Simulates the proxy setting req.URL.Host = req.Host where Host includes :443
		reqURL, _ := url.Parse("https://brex.okta.com:443/.well-known/openid-configuration")
		req := &http.Request{Method: "GET", URL: reqURL}
		rule := types.StaticRule{
			URLPattern: "https://brex.okta.com/",
			MatchType:  "prefix",
			Action:     "allow",
		}
		if !staticRuleMatches(rule, req) {
			t.Error("expected rule https://brex.okta.com/ to match request with :443 port")
		}
	})

	t.Run("staticRuleMatches normalises :443 in rule pattern", func(t *testing.T) {
		reqURL, _ := url.Parse("https://brex.okta.com/.well-known/openid-configuration")
		req := &http.Request{Method: "GET", URL: reqURL}
		rule := types.StaticRule{
			URLPattern: "https://brex.okta.com:443/",
			MatchType:  "prefix",
			Action:     "allow",
		}
		if !staticRuleMatches(rule, req) {
			t.Error("expected rule with :443 to match request without port")
		}
	})

	t.Run("MatchesStaticRules normalises default port", func(t *testing.T) {
		rules := []types.StaticRule{
			{URLPattern: "https://brex.okta.com/", MatchType: "prefix", Action: "allow"},
		}
		matched, action := MatchesStaticRules("GET", "https://brex.okta.com:443/.well-known/openid-configuration", rules)
		if !matched || action != "allow" {
			t.Errorf("expected allow, got matched=%v action=%q", matched, action)
		}
	})

	t.Run("non-default port is preserved", func(t *testing.T) {
		rules := []types.StaticRule{
			{URLPattern: "https://example.com/", MatchType: "prefix", Action: "allow"},
		}
		matched, _ := MatchesStaticRules("GET", "https://example.com:8443/foo", rules)
		if matched {
			t.Error("expected non-default port :8443 to NOT match rule without port")
		}
	})
}

func TestGlobRegexpCacheBounded(t *testing.T) {
	// Reset cache before and after the test to avoid interfering with other tests.
	resetGlobCache()
	t.Cleanup(resetGlobCache)

	t.Run("cache stores entries", func(t *testing.T) {
		resetGlobCache()
		_, err := globToRegexp("*.example.com/*")
		if err != nil {
			t.Fatalf("globToRegexp failed: %v", err)
		}
		if n := globCacheLen(); n != 1 {
			t.Errorf("expected cache len 1, got %d", n)
		}
	})

	t.Run("duplicate pattern does not grow cache", func(t *testing.T) {
		resetGlobCache()
		for i := 0; i < 10; i++ {
			_, err := globToRegexp("*.example.com/*")
			if err != nil {
				t.Fatalf("globToRegexp failed: %v", err)
			}
		}
		if n := globCacheLen(); n != 1 {
			t.Errorf("expected cache len 1 for duplicate pattern, got %d", n)
		}
	})

	t.Run("cache is bounded at globRegexpCacheMaxSize", func(t *testing.T) {
		resetGlobCache()
		// Fill cache to its maximum size.
		for i := 0; i < globRegexpCacheMaxSize; i++ {
			pattern := fmt.Sprintf("host%d.example.com/*", i)
			_, err := globToRegexp(pattern)
			if err != nil {
				t.Fatalf("globToRegexp(%q) failed: %v", pattern, err)
			}
		}
		if n := globCacheLen(); n != globRegexpCacheMaxSize {
			t.Errorf("expected cache len %d, got %d", globRegexpCacheMaxSize, n)
		}

		// One more entry should trigger eviction (clear + insert).
		_, err := globToRegexp("overflow.example.com/*")
		if err != nil {
			t.Fatalf("globToRegexp(overflow) failed: %v", err)
		}
		if n := globCacheLen(); n != 1 {
			t.Errorf("expected cache len 1 after eviction, got %d", n)
		}
	})

	t.Run("cached regexp still works after eviction", func(t *testing.T) {
		resetGlobCache()
		// Insert a pattern, then trigger eviction, then re-insert.
		_, err := globToRegexp("*.example.com/*")
		if err != nil {
			t.Fatalf("globToRegexp failed: %v", err)
		}
		// Fill up to trigger eviction.
		for i := 0; i < globRegexpCacheMaxSize; i++ {
			globToRegexp(fmt.Sprintf("filler%d.example.com/*", i))
		}
		// The original pattern should still work (re-compiled on miss).
		re, err := globToRegexp("*.example.com/*")
		if err != nil {
			t.Fatalf("globToRegexp failed after eviction: %v", err)
		}
		if !re.MatchString("api.example.com/foo") {
			t.Error("expected re-compiled pattern to still match")
		}
	})

	t.Run("concurrent access is safe", func(t *testing.T) {
		resetGlobCache()
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				pattern := fmt.Sprintf("concurrent%d.example.com/*", n)
				re, err := globToRegexp(pattern)
				if err != nil {
					t.Errorf("globToRegexp(%q) failed: %v", pattern, err)
					return
				}
				if re == nil {
					t.Errorf("globToRegexp(%q) returned nil", pattern)
				}
			}(i)
		}
		wg.Wait()
		// Cache should be bounded.
		if n := globCacheLen(); n > globRegexpCacheMaxSize {
			t.Errorf("cache exceeded max size: got %d, max %d", n, globRegexpCacheMaxSize)
		}
	})
}
