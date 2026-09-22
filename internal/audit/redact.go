package audit

import (
	"net/http"
	"strings"

	"github.com/brexhq/CrabTrap/pkg/types"
)

const redactedHeaderValue = "[REDACTED]"

var sensitiveHeaders = map[string]struct{}{
	"api-key":             {},
	"authorization":       {},
	"cookie":              {},
	"private-token":       {},
	"proxy-authorization": {},
	"set-cookie":          {},
	"x-amz-security-token": {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-goog-api-key":      {},
}

// RedactEntryHeaders returns a copy of entry with credential-bearing request
// and response header values removed. The caller's header maps are not mutated.
func RedactEntryHeaders(entry types.AuditEntry) types.AuditEntry {
	entry.RequestHeaders = RedactHeaders(entry.RequestHeaders)
	entry.ResponseHeaders = RedactHeaders(entry.ResponseHeaders)
	return entry
}

// RedactHeaders clones headers and replaces sensitive values while preserving
// header names so the audit trail still records that a credential was present.
func RedactHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}

	redacted := headers.Clone()
	for name := range redacted {
		if _, sensitive := sensitiveHeaders[strings.ToLower(name)]; sensitive {
			redacted[name] = []string{redactedHeaderValue}
		}
	}
	return redacted
}
