package alerting

import (
	"testing"
)

func TestNormalizePattern(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"REST with query params", "https://api.github.com/repos/org/repo?page=2", "api.github.com/repos/org"},
		{"REST deep path", "https://api.github.com/repos/org/repo/pulls/123", "api.github.com/repos/org"},
		{"default port stripped", "https://api.stripe.com:443/v1/charges", "api.stripe.com/v1/charges"},
		{"default http port stripped", "http://example.com:80/a/b/c/d", "example.com/a/b"},
		{"non-default port kept", "http://example.com:8080/a/b/c", "example.com:8080/a/b"},
		{"trailing slash", "https://api.example.com/", "api.example.com"},
		{"no path", "https://api.example.com", "api.example.com"},
		{"single segment", "https://api.example.com/single", "api.example.com/single"},
		{"fragment stripped", "https://host.com/a/b/c?x=1&y=2#frag", "host.com/a/b"},
		{"invalid URL passthrough", "not-a-url", "not-a-url"},
		{"graphql grouped by url", "https://api.github.com/graphql", "api.github.com/graphql"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePattern(tt.url)
			if got != tt.want {
				t.Errorf("normalizePattern(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
