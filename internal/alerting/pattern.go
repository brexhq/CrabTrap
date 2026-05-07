package alerting

import (
	"net/url"
	"strings"
)

// normalizePattern extracts a stable grouping key from a URL.
// Strips query params, fragment, default ports, and keeps only the host
// plus the first two path segments.
//
// Examples:
//
//	"https://api.github.com/repos/org/repo?page=2" → "api.github.com/repos/org"
//	"https://api.stripe.com:443/v1/charges"        → "api.stripe.com/v1/charges"
//	"http://example.com/a/b/c/d"                   → "example.com/a/b"
//
// Note: GraphQL endpoints that share a single URL (e.g., POST /graphql) will
// be grouped together. Operation-level dedup would require access to request
// bodies, which are stripped before broadcast for security reasons.
func normalizePattern(rawURL string) string {
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

	return host + path
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
