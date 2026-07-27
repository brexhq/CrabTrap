package approval

import (
	"testing"

	"github.com/brexhq/CrabTrap/pkg/types"
)

// TestStaticRuleHostCaseInsensitive checks that static rules match hosts
// without regard to case. Host names are case-insensitive (RFC 4343), so a
// rule written in lower case has to match a request that varies the case of
// the host; both reach the same server. Paths stay case-sensitive.
func TestStaticRuleHostCaseInsensitive(t *testing.T) {
	rule := func(pattern, matchType, action string) []types.StaticRule {
		return []types.StaticRule{{URLPattern: pattern, MatchType: matchType, Action: action}}
	}

	cases := []struct {
		name       string
		rules      []types.StaticRule
		url        string
		wantAction string // "" means no rule should match
	}{
		// allow rules must still match when the request varies host case
		{"prefix allow, upper host", rule("https://api.example.com/", "prefix", "allow"), "https://API.EXAMPLE.COM/v1", "allow"},
		{"glob allow, mixed subdomain", rule("*.example.com/*", "glob", "allow"), "https://API.Example.com/v1/users", "allow"},

		// deny rules likewise
		{"prefix deny, upper host", rule("https://internal.example.com/", "prefix", "deny"), "https://INTERNAL.EXAMPLE.COM/secrets", "deny"},
		{"prefix deny, mixed host", rule("https://internal.example.com/", "prefix", "deny"), "https://Internal.Example.com/secrets", "deny"},
		{"exact deny, mixed host", rule("https://internal.example.com/x", "exact", "deny"), "https://Internal.Example.com/x", "deny"},
		{"glob deny, upper host", rule("internal.example.com/*", "glob", "deny"), "https://INTERNAL.EXAMPLE.COM/secrets", "deny"},

		// a pattern authored in upper case must match a lower-case request too
		{"upper-case rule, lower-case url", rule("https://API.EXAMPLE.COM/", "prefix", "allow"), "https://api.example.com/v1", "allow"},

		// only the authority is folded, so path case still matters
		{"path case differs", rule("https://api.example.com/Users", "exact", "allow"), "https://api.example.com/users", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, action := MatchesStaticRules("POST", tc.url, tc.rules)
			if tc.wantAction == "" {
				if matched {
					t.Errorf("MatchesStaticRules(%q) matched with action %q, want no match", tc.url, action)
				}
				return
			}
			if !matched || action != tc.wantAction {
				t.Errorf("MatchesStaticRules(%q) = (matched=%v, action=%q), want (true, %q)",
					tc.url, matched, action, tc.wantAction)
			}
		})
	}
}
