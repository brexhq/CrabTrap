// Package judgeprompt serializes an HTTP request into the JSON object used
// as the user-message payload for LLM-judge and probe-runner calls. Both
// callers share this exact format so that semantic analysis (judge) and
// probe activations score the same wire representation.
package judgeprompt

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"sort"
	"strings"
)

// Default size caps. Callers may override MaxBodyBytes; the other caps are
// fixed since they bound the prompt "chrome" rather than the user payload.
const (
	DefaultMaxBodyBytes = 16384
	MaxURLBytes         = 2048
	MaxHeaderBytes      = 4096
	MaxHeaderValueBytes = 512
)

// SecurityHeaders lists headers that are prioritised when the total header
// content exceeds MaxHeaderBytes. They are included first (in this order)
// before any remaining headers.
var SecurityHeaders = []string{
	"Host",
	"Content-Type",
	"Content-Encoding",
	"Transfer-Encoding",
	"Authorization",
	"Content-Length",
	"Origin",
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"Cookie",
}

// RequestJSON is the structured representation of an HTTP request sent to the
// LLM judge / probes. Using JSON ensures all user-controlled content (URLs,
// headers, body) is properly escaped, preventing prompt injection via request
// data.
type RequestJSON struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`

	// Warnings are populated when truncation occurs.
	Warnings []string `json:"warnings,omitempty"`

	// MultipartSummary is included when the body is multipart and was truncated.
	MultipartSummary string `json:"multipart_summary,omitempty"`
}

// BuildUserMessage constructs the user message describing the HTTP request
// as a JSON object. JSON encoding naturally escapes any injection attempts
// in URLs, headers, or body content.
//
// maxBodyBytes caps the body payload; values ≤ 0 fall back to DefaultMaxBodyBytes.
// The Content-Type header is looked up internally so callers pass raw headers.
func BuildUserMessage(method, rawURL string, headers http.Header, body string, maxBodyBytes int) string {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	contentType := headers.Get("Content-Type")

	req := RequestJSON{
		Method:  method,
		Headers: make(map[string]string),
	}

	var warnings []string

	if len(rawURL) > MaxURLBytes {
		req.URL = rawURL[:MaxURLBytes]
		warnings = append(warnings, fmt.Sprintf(
			"URL truncated at %d of %d characters",
			MaxURLBytes, len(rawURL),
		))
	} else {
		req.URL = rawURL
	}

	headerStr, headerWarning := BuildHeaderMap(headers)
	req.Headers = headerStr
	if headerWarning != "" {
		warnings = append(warnings, headerWarning)
	}

	bodyStr := body
	if len(body) > maxBodyBytes {
		bodyStr = body[:maxBodyBytes]
		warnings = append(warnings, fmt.Sprintf(
			"Body truncated at %d of %d bytes — content beyond this point was NOT evaluated. Exercise caution.",
			maxBodyBytes, len(body),
		))

		if summary := SummarizeMultipartParts(contentType, body); summary != "" {
			req.MultipartSummary = summary
		}
	}
	req.Body = bodyStr

	if len(warnings) > 0 {
		req.Warnings = warnings
	}

	out, _ := json.Marshal(req)
	return string(out)
}

// BuildHeaderMap returns a map of header key→value strings for the JSON
// request object, capped at MaxHeaderBytes total. Security-relevant headers
// are included first so they are never displaced by attacker-controlled header
// inflation. Individual header values are capped at MaxHeaderValueBytes.
// Multiple values for the same key are joined with ", ".
// Returns a warning string if headers were truncated.
func BuildHeaderMap(headers http.Header) (map[string]string, string) {
	capValue := func(v string) string {
		if len(v) <= MaxHeaderValueBytes {
			return v
		}
		return v[:MaxHeaderValueBytes] + fmt.Sprintf("...[truncated, %d bytes total]", len(v))
	}

	result := make(map[string]string)
	written := 0
	emitted := make(map[string]bool)

	addHeader := func(key string) bool {
		values := headers.Values(key)
		if len(values) == 0 {
			return true
		}
		joined := capValue(strings.Join(values, ", "))
		size := len(key) + len(joined)
		if written+size > MaxHeaderBytes {
			return false
		}
		result[key] = joined
		written += size
		emitted[http.CanonicalHeaderKey(key)] = true
		return true
	}

	for _, key := range SecurityHeaders {
		if !addHeader(key) {
			return result, fmt.Sprintf(
				"Headers truncated at %d of %d total header bytes to prevent prompt inflation",
				written, totalHeaderBytes(headers),
			)
		}
	}

	remaining := make([]string, 0, len(headers))
	for key := range headers {
		if !emitted[http.CanonicalHeaderKey(key)] {
			remaining = append(remaining, key)
		}
	}
	sort.Strings(remaining)

	for _, key := range remaining {
		if !addHeader(key) {
			return result, fmt.Sprintf(
				"Headers truncated at %d of %d total header bytes to prevent prompt inflation",
				written, totalHeaderBytes(headers),
			)
		}
	}

	return result, ""
}

func totalHeaderBytes(headers http.Header) int {
	total := 0
	for key, values := range headers {
		for _, v := range values {
			total += len(key) + 2 + len(v) + 1
		}
	}
	return total
}

const (
	maxSummaryBytes    = 8192
	maxFieldDisplayLen = 128
	maxPartPreview     = 512
)

func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func isTextualPart(ct string) bool {
	if ct == "" {
		return true
	}
	lower := strings.ToLower(ct)
	if strings.HasPrefix(lower, "text/") {
		return true
	}
	for _, prefix := range []string{"application/json", "application/xml", "application/x-www-form-urlencoded"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// SummarizeMultipartParts parses a multipart body and returns a human-readable
// summary of every part including metadata and text content previews.
// Returns "" if the content is not multipart or parsing fails entirely.
func SummarizeMultipartParts(contentType, body string) string {
	if contentType == "" {
		return ""
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return ""
	}
	boundary := params["boundary"]
	if boundary == "" {
		return ""
	}

	reader := multipart.NewReader(strings.NewReader(body), boundary)

	const maxParts = 1000
	var sb strings.Builder
	var partCount int
	complete := false
	summaryCapped := false

	for i := 0; i < maxParts; i++ {
		part, partErr := reader.NextPart()
		if partErr == io.EOF {
			complete = true
			break
		}
		if partErr != nil {
			break
		}
		partCount++

		name := truncateField(part.FormName(), maxFieldDisplayLen)
		filename := truncateField(part.FileName(), maxFieldDisplayLen)
		ct := truncateField(part.Header.Get("Content-Type"), maxFieldDisplayLen)

		preview, _ := io.ReadAll(io.LimitReader(part, maxPartPreview+1))
		remaining, _ := io.Copy(io.Discard, part)
		size := int64(len(preview)) + remaining

		desc := fmt.Sprintf("  Part %d: name=%q", i+1, name)
		if filename != "" {
			desc += fmt.Sprintf(", filename=%q", filename)
		}
		if ct != "" {
			desc += fmt.Sprintf(", content-type=%s", ct)
		}
		desc += fmt.Sprintf(", size=%d bytes", size)

		if isTextualPart(ct) && len(preview) > 0 {
			previewStr := string(preview)
			if int64(len(preview)) > maxPartPreview {
				previewStr = string(preview[:maxPartPreview]) + "..."
			}
			desc += fmt.Sprintf("\n    value: %s", previewStr)
		}

		sb.WriteString(desc)
		sb.WriteString("\n")

		if sb.Len() > maxSummaryBytes {
			summaryCapped = true
			break
		}
	}

	if partCount == 0 {
		return ""
	}

	header := fmt.Sprintf("[Multipart body summary — %d part(s) parsed", partCount)
	if complete {
		header += " (complete)"
	} else {
		header += " (body may be truncated; more parts may exist)"
	}
	header += ":\n"

	footer := ""
	if summaryCapped {
		footer = fmt.Sprintf("  (summary truncated at %d bytes; more parts may exist)\n", maxSummaryBytes)
	} else if partCount == maxParts {
		footer = fmt.Sprintf("  (listing capped at %d parts; more may exist)\n", maxParts)
	}

	return header + sb.String() + footer + "]"
}
