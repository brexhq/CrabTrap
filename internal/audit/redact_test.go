package audit

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/brexhq/CrabTrap/pkg/types"
)

func TestRedactEntryHeaders(t *testing.T) {
	requestHeaders := http.Header{
		"Api-Key":             []string{"api-secret"},
		"authorization":       []string{"Bearer secret"},
		"Cookie":              []string{"session=secret"},
		"Private-Token":       []string{"private-secret"},
		"Proxy-Authorization": []string{"Basic secret"},
		"X-Amz-Security-Token": []string{"aws-secret"},
		"X-Api-Key":           []string{"api-secret"},
		"X-Auth-Token":        []string{"token-secret"},
		"X-Goog-Api-Key":      []string{"google-secret"},
		"Content-Type":        []string{"application/json"},
	}
	responseHeaders := http.Header{
		"Set-Cookie": []string{"session=secret", "csrf=secret"},
		"X-Trace-Id": []string{"trace-123"},
	}
	entry := types.AuditEntry{RequestHeaders: requestHeaders, ResponseHeaders: responseHeaders}

	got := RedactEntryHeaders(entry)

	for _, name := range []string{"Api-Key", "authorization", "Cookie", "Private-Token", "Proxy-Authorization", "X-Amz-Security-Token", "X-Api-Key", "X-Auth-Token", "X-Goog-Api-Key"} {
		if values := got.RequestHeaders[name]; !reflect.DeepEqual(values, []string{redactedHeaderValue}) {
			t.Errorf("request header %s = %v, want redacted", name, values)
		}
	}
	if values := got.ResponseHeaders.Values("Set-Cookie"); !reflect.DeepEqual(values, []string{redactedHeaderValue}) {
		t.Errorf("response Set-Cookie = %v, want redacted", values)
	}
	if values := got.RequestHeaders.Values("Content-Type"); !reflect.DeepEqual(values, []string{"application/json"}) {
		t.Errorf("request Content-Type = %v, want unchanged", values)
	}
	if values := got.ResponseHeaders.Values("X-Trace-Id"); !reflect.DeepEqual(values, []string{"trace-123"}) {
		t.Errorf("response X-Trace-Id = %v, want unchanged", values)
	}
	if values := requestHeaders["authorization"]; !reflect.DeepEqual(values, []string{"Bearer secret"}) {
		t.Errorf("caller's Authorization header was mutated: %v", values)
	}
	if values := responseHeaders.Values("Set-Cookie"); !reflect.DeepEqual(values, []string{"session=secret", "csrf=secret"}) {
		t.Errorf("caller's Set-Cookie header was mutated: %v", values)
	}
}

func TestRedactHeadersPreservesNil(t *testing.T) {
	if got := RedactHeaders(nil); got != nil {
		t.Fatalf("RedactHeaders(nil) = %v, want nil", got)
	}
}
