package llm

import (
	"errors"
	"strings"
)

// ErrContextLength is wrapped by an adapter when a request was rejected because
// it exceeded the model's context window. Callers detect it with errors.Is.
//
// Adapters set it ONLY for genuine context-overflow signals — an HTTP 400
// (Anthropic/OpenAI) or a Bedrock ValidationException whose message indicates
// the input is too long. It is never set for 429 throttling / rate-limit
// errors, so those are not misclassified as context overflow.
var ErrContextLength = errors.New("model context length exceeded")

// bodyIndicatesContextLength reports whether a provider error message describes a
// context-window overflow. It is the discriminator applied AFTER the status code
// (or exception type) has already confirmed a client-request error rather than a
// 429: only OpenAI emits a distinct machine code (context_length_exceeded), so
// for Anthropic and Bedrock the message text is the only available signal.
func bodyIndicatesContextLength(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "context_length_exceeded") || // OpenAI code
		strings.Contains(s, "is too long") || // Anthropic "prompt is too long", Bedrock "input is too long"
		strings.Contains(s, "maximum context length") || // OpenAI message
		strings.Contains(s, "context window")
}
