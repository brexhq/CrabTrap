package alerting

import (
	"testing"
)

func TestNormalizePattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://api.github.com/repos/org/repo?page=2", "api.github.com/repos/org"},
		{"https://api.github.com/repos/org/repo/pulls/123", "api.github.com/repos/org"},
		{"https://api.stripe.com:443/v1/charges", "api.stripe.com/v1/charges"},
		{"http://example.com:80/a/b/c/d", "example.com/a/b"},
		{"http://example.com:8080/a/b/c", "example.com:8080/a/b"},
		{"https://api.example.com/", "api.example.com"},
		{"https://api.example.com", "api.example.com"},
		{"https://api.example.com/single", "api.example.com/single"},
		{"https://host.com/a/b/c?x=1&y=2#frag", "host.com/a/b"},
		{"not-a-url", "not-a-url"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePattern(tt.input)
			if got != tt.want {
				t.Errorf("normalizePattern(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
