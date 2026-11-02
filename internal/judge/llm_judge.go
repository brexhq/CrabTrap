package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"sort"
	"strings"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

const maxBodyBytes = 16384
const maxURLBytes = 2048
const maxHeaderBytes = 4096
const maxHeaderValueBytes = 512

// securityHeaders lists headers that are prioritised when the total header
// content exceeds maxHeaderBytes.  They are included first (in this order)
// before any remaining headers.
var securityHeaders = []string{
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

// JudgeResult holds the parsed outcome of one LLM judge call.
type JudgeResult struct {
	Decision     types.DecisionType
	Reason       string
	Model        string // actual model ID used
	DurationMs   int
	InputTokens  int
	OutputTokens int
	RawOutput    string // raw model text before parsing
	// Score is an optional model-specific confidence signal. For Jev it is the
	// noul p(violates) probability in [0,1]. LLM judges leave it nil.
	Score *float64
	// DecidedBy overrides the approved_by value the approval manager records.
	// "jev" means Jev decided alone. "jev+llm" means Jev was consulted first
	// and the LLM made the final decision. Empty means a plain LLM decision,
	// and the manager uses "llm".
	DecidedBy string
}

// LLMJudge evaluates HTTP requests against an LLM policy via an Adapter.
type LLMJudge struct{ adapter llm.Adapter }

// NewLLMJudge constructs an LLMJudge backed by the given adapter.
func NewLLMJudge(adapter llm.Adapter) *LLMJudge {
	return &LLMJudge{adapter: adapter}
}

// Evaluate calls the adapter and returns ALLOW or DENY.
// On error, the returned JudgeResult still has Model and DurationMs populated.
func (j *LLMJudge) Evaluate(ctx context.Context, method, rawURL string, headers http.Header, body string, policy types.LLMPolicy) (JudgeResult, error) {
	partial := JudgeResult{Model: j.adapter.ModelID()}

	contentType := headers.Get("Content-Type")
	resp, err := j.adapter.Complete(ctx, llm.Request{
		System:            buildSystemPrompt(policy.Prompt),
		Messages:          []llm.Message{{Role: "user", Content: buildUserMessage(method, rawURL, headers, body, contentType)}},
		MaxTokens:         512,
		CacheSystemPrompt: true,
	})
	partial.DurationMs = resp.DurationMs
	if err != nil {
		partial.RawOutput = fmt.Sprintf("adapter complete failed: %v", err)
		return partial, fmt.Errorf("adapter complete failed: %w", err)
	}

	partial.InputTokens = resp.InputTokens
	partial.OutputTokens = resp.OutputTokens
	partial.RawOutput = resp.Text

	type decisionJSON struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	var d decisionJSON
	if err := json.Unmarshal([]byte(llm.StripCodeFences(resp.Text)), &d); err != nil {
		return partial, fmt.Errorf("failed to parse decision JSON from model output: %w (response: %s)", err, resp.Text)
	}

	partial.Reason = d.Reason
	d.Decision = strings.ToUpper(strings.TrimSpace(d.Decision))
	switch types.DecisionType(d.Decision) {
	case types.DecisionAllow:
		partial.Decision = types.DecisionAllow
		return partial, nil
	case types.DecisionDeny:
		partial.Decision = types.DecisionDeny
		return partial, nil
	default:
		return partial, fmt.Errorf("unknown decision %q from model", d.Decision)
	}
}

// buildSystemPrompt constructs the system prompt for the judge.
//
// The policy is embedded as a JSON-escaped value inside a structured JSON object.
// This prevents prompt injection via policy content — any special characters,
// delimiters, or instruction-like text in the policy are safely escaped by
// json.Marshal rather than concatenated as raw text.
func buildSystemPrompt(policyPrompt string) string {
	policyJSON, _ := json.Marshal(policyPrompt)
	return `You are a security policy enforcement agent. You will receive an HTTP request as a structured JSON object and must decide whether it is ALLOWED or DENIED.

The policy to enforce is provided below as a JSON-encoded string. Parse the string value to read the policy:
{"policy":` + string(policyJSON) + `}

Respond ONLY with valid JSON in this exact format (no other text):
{"decision":"ALLOW","reason":"brief explanation"}
or
{"decision":"DENY","reason":"brief explanation"}`
}

// requestJSON is the structured representation of an HTTP request sent to the
// LLM judge. Using JSON ensures all user-controlled content (URLs, headers,
// body) is properly escaped, preventing prompt injection via request data.
type requestJSON struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`

	// Warnings are populated when truncation occurs.
	Warnings []string `json:"warnings,omitempty"`

	// MultipartSummary is included when the body is multipart and was truncated.
	MultipartSummary string `json:"multipart_summary,omitempty"`
}

// buildUserMessage constructs the user message describing the HTTP request
// as a JSON object. JSON encoding naturally escapes any injection attempts
// in URLs, headers, or body content.
// contentType is the value of the Content-Type header, used to detect multipart bodies.
func buildUserMessage(method, rawURL string, headers http.Header, body, contentType string) string {
	req := requestJSON{
		Method:  method,
		Headers: make(map[string]string),
	}

	var warnings []string

	// Cap URL length to prevent inflation attacks that displace body content.
	if len(rawURL) > maxURLBytes {
		req.URL = rawURL[:maxURLBytes]
		warnings = append(warnings, fmt.Sprintf(
			"URL truncated at %d of %d characters",
			maxURLBytes, len(rawURL),
		))
	} else {
		req.URL = rawURL
	}

	// Build headers with size caps.
	headerStr, headerWarning := buildHeaderMap(headers)
	req.Headers = headerStr
	if headerWarning != "" {
		warnings = append(warnings, headerWarning)
	}

	// Body with truncation.
	bodyStr := body
	if len(body) > maxBodyBytes {
		bodyStr = body[:maxBodyBytes]
		warnings = append(warnings, fmt.Sprintf(
			"Body truncated at %d of %d bytes — content beyond this point was NOT evaluated. Exercise caution.",
			maxBodyBytes, len(body),
		))

		// For multipart content, summarise all parts so the LLM knows what is hidden.
		if summary := summarizeMultipartParts(contentType, body); summary != "" {
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

// buildHeaderMap returns a map of header key→value strings for the JSON request
// object, capped at maxHeaderBytes total. Security-relevant headers are included
// first so they are never displaced by attacker-controlled header inflation.
// Individual header values are capped at maxHeaderValueBytes.
// Multiple values for the same key are joined with ", ".
// Returns a warning string if headers were truncated.
func buildHeaderMap(headers http.Header) (map[string]string, string) {
	capValue := func(v string) string {
		if len(v) <= maxHeaderValueBytes {
			return v
		}
		return v[:maxHeaderValueBytes] + fmt.Sprintf("...[truncated, %d bytes total]", len(v))
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
		if written+size > maxHeaderBytes {
			return false
		}
		result[key] = joined
		written += size
		emitted[http.CanonicalHeaderKey(key)] = true
		return true
	}

	// Phase 1: security-relevant headers, in priority order.
	for _, key := range securityHeaders {
		if !addHeader(key) {
			return result, fmt.Sprintf(
				"Headers truncated at %d of %d total header bytes to prevent prompt inflation",
				written, totalHeaderBytes(headers),
			)
		}
	}

	// Phase 2: remaining headers, sorted alphabetically for deterministic output.
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

// totalHeaderBytes returns the total byte count of all header lines in
// "Key: Value\n" format.
func totalHeaderBytes(headers http.Header) int {
	total := 0
	for key, values := range headers {
		for _, v := range values {
			total += len(key) + 2 + len(v) + 1 // "Key: Value\n"
		}
	}
	return total
}

const (
	maxSummaryBytes    = 8192 // total summary output cap
	maxFieldDisplayLen = 128  // max length for name/filename/content-type values
	maxPartPreview     = 512  // text content preview per part
)

// truncateField caps a string at max bytes, appending "..." if truncated.
func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// isTextualPart returns true if the part's content-type indicates text content
// whose value is meaningful for policy evaluation.
func isTextualPart(ct string) bool {
	if ct == "" {
		return true // form fields with no explicit content-type are text
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

// summarizeMultipartParts parses a multipart body and returns a human-readable
// summary of every part including metadata and text content previews.
// Returns "" if the content is not multipart or parsing fails entirely.
//
// For textual parts (form fields, JSON, XML), a preview of the value is
// included so the LLM can evaluate content beyond the truncation window.
// The total summary is capped at maxSummaryBytes and individual field values
// at maxFieldDisplayLen to bound output size.
func summarizeMultipartParts(contentType, body string) string {
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
			break // parse error or truncated body
		}
		partCount++

		name := truncateField(part.FormName(), maxFieldDisplayLen)
		filename := truncateField(part.FileName(), maxFieldDisplayLen)
		ct := truncateField(part.Header.Get("Content-Type"), maxFieldDisplayLen)

		// Read a preview of the part content, then drain the rest for size.
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

		// Include text preview for non-binary parts so the LLM can
		// evaluate field values beyond the body truncation window.
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
