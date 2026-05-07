package alerting

import (
	"encoding/json"
	"net/url"
	"strings"
)

// normalizePattern extracts a stable grouping key from a URL and optional
// request body. Strips query params, fragment, default ports, and keeps
// the host plus the first two path segments. For GraphQL endpoints, the
// operation name is appended to distinguish different operations on the
// same URL.
//
// Examples:
//
//	"https://api.github.com/repos/org/repo?page=2" → "api.github.com/repos/org"
//	"https://api.stripe.com:443/v1/charges"        → "api.stripe.com/v1/charges"
//	"https://api.github.com/graphql" (body has operationName: "CreateRepo") → "api.github.com/graphql:CreateRepo"
func normalizePattern(rawURL, body string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}

	host := u.Hostname()
	port := u.Port()
	if port != "" && !isDefaultPort(u.Scheme, port) {
		host = host + ":" + port
	}

	path := firstNSegments(u.Path, 2)
	if path == "" {
		return host
	}

	pattern := host + path

	if isGraphQLPath(u.Path) {
		if op := extractGraphQLOperation(body); op != "" {
			pattern += ":" + op
		}
	}

	return pattern
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
}

func firstNSegments(path string, n int) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return ""
	}

	segments := strings.SplitN(path[1:], "/", n+1) // skip leading /
	if len(segments) > n {
		segments = segments[:n]
	}
	return "/" + strings.Join(segments, "/")
}

func isGraphQLPath(path string) bool {
	p := strings.TrimRight(strings.ToLower(path), "/")
	return strings.HasSuffix(p, "/graphql") || strings.HasSuffix(p, "/gql") || p == "/graphql" || p == "/gql"
}

func extractGraphQLOperation(body string) string {
	if body == "" {
		return ""
	}
	var req struct {
		OperationName string `json:"operationName"`
		Query         string `json:"query"`
	}
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return ""
	}
	if req.OperationName != "" {
		return req.OperationName
	}
	return parseOperationFromQuery(req.Query)
}

// parseOperationFromQuery extracts the operation name from a GraphQL query string.
// e.g. "mutation CreateRepo($input: ...) { ... }" → "CreateRepo"
func parseOperationFromQuery(query string) string {
	query = strings.TrimSpace(query)
	for _, prefix := range []string{"query", "mutation", "subscription"} {
		if strings.HasPrefix(query, prefix) {
			rest := strings.TrimSpace(query[len(prefix):])
			// Extract the name (stops at space, paren, or brace)
			name := ""
			for _, c := range rest {
				if c == '(' || c == '{' || c == ' ' || c == '\n' {
					break
				}
				name += string(c)
			}
			if name != "" {
				return name
			}
		}
	}
	return ""
}
