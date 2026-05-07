package alerting

import (
	"testing"
)

func TestNormalizePattern(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		body  string
		want  string
	}{
		{"REST with query params", "https://api.github.com/repos/org/repo?page=2", "", "api.github.com/repos/org"},
		{"REST deep path", "https://api.github.com/repos/org/repo/pulls/123", "", "api.github.com/repos/org"},
		{"default port stripped", "https://api.stripe.com:443/v1/charges", "", "api.stripe.com/v1/charges"},
		{"default http port stripped", "http://example.com:80/a/b/c/d", "", "example.com/a/b"},
		{"non-default port kept", "http://example.com:8080/a/b/c", "", "example.com:8080/a/b"},
		{"trailing slash", "https://api.example.com/", "", "api.example.com"},
		{"no path", "https://api.example.com", "", "api.example.com"},
		{"single segment", "https://api.example.com/single", "", "api.example.com/single"},
		{"fragment stripped", "https://host.com/a/b/c?x=1&y=2#frag", "", "host.com/a/b"},
		{"invalid URL passthrough", "not-a-url", "", "not-a-url"},
		// GraphQL with operationName
		{"graphql with operationName", "https://api.github.com/graphql", `{"query":"mutation { ... }","operationName":"CreateRepo"}`, "api.github.com/graphql:CreateRepo"},
		// GraphQL with operation in query
		{"graphql operation from query", "https://api.example.com/graphql", `{"query":"mutation DeleteUser($id: ID!) { deleteUser(id: $id) }"}`, "api.example.com/graphql:DeleteUser"},
		// GraphQL anonymous query
		{"graphql anonymous", "https://api.example.com/graphql", `{"query":"{ viewer { login } }"}`, "api.example.com/graphql"},
		// GraphQL with /gql path
		{"gql path", "https://api.example.com/gql", `{"query":"query GetUser { user { id } }","operationName":"GetUser"}`, "api.example.com/gql:GetUser"},
		// Non-GraphQL with body (body ignored)
		{"rest ignores body", "https://api.stripe.com/v1/charges", `{"amount":100}`, "api.stripe.com/v1/charges"},
		// GraphQL with empty body
		{"graphql no body", "https://api.example.com/graphql", "", "api.example.com/graphql"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePattern(tt.url, tt.body)
			if got != tt.want {
				t.Errorf("normalizePattern(%q, %q) = %q, want %q", tt.url, tt.body, got, tt.want)
			}
		})
	}
}
