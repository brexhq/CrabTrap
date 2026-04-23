package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// BedrockAdapter calls Anthropic models via AWS Bedrock.
type BedrockAdapter struct {
	client  *bedrockruntime.Client
	model   string
	timeout time.Duration

	// invokeFunc, when non-nil, replaces client.InvokeModel for testing.
	invokeFunc func(ctx context.Context, input *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error)

	*Resilience
}

// NewBedrockAdapter creates a BedrockAdapter using the default AWS credential chain.
func NewBedrockAdapter(model, awsRegion string, timeout time.Duration, opts ...ResilienceOption) (*BedrockAdapter, error) {
	cfgOpts := []func(*awsconfig.LoadOptions) error{}
	if awsRegion != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(awsRegion))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	client := bedrockruntime.NewFromConfig(awsCfg)

	a := &BedrockAdapter{
		client:     client,
		model:      model,
		timeout:    timeout,
		Resilience: NewResilience(opts...),
	}
	return a, nil
}

func (a *BedrockAdapter) ModelID() string { return a.model }

// Complete sends req to Bedrock and returns the model's response.
// When req.Tools is non-empty the model may return ToolCalls instead of (or in addition to) Text.
//
// Complete enforces a concurrency semaphore and a circuit breaker. If the circuit
// is open (too many consecutive failures), it returns an error immediately without
// calling the Bedrock API.
func (a *BedrockAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	if err := a.Acquire(ctx, "bedrock"); err != nil {
		return Response{}, err
	}
	defer a.Release()

	timeout := a.timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 512
	}

	// Build messages — content is either a string (simple text) or a content-block array.
	msgs := make([]map[string]interface{}, 0, len(req.Messages))
	for _, m := range req.Messages {
		msg, err := buildAnthropicMessage(m)
		if err != nil {
			return Response{}, fmt.Errorf("build message: %w", err)
		}
		msgs = append(msgs, msg)
	}

	body := map[string]interface{}{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        maxTokens,
		"messages":          msgs,
	}
	if req.System != "" {
		if req.CacheSystemPrompt {
			// Use the content-block array format so Bedrock can cache the system prompt.
			// cache_control is placed on the last (and only) block — Bedrock will cache
			// everything up to that breakpoint. Requires ≥1 024 tokens to take effect;
			// shorter prompts are silently sent as plain text by the service.
			body["system"] = []map[string]interface{}{{
				"type":          "text",
				"text":          req.System,
				"cache_control": map[string]string{"type": "ephemeral"},
			}}
		} else {
			body["system"] = req.System
		}
	}
	if len(req.Tools) > 0 {
		tools := make([]map[string]interface{}, len(req.Tools))
		for i, t := range req.Tools {
			tools[i] = map[string]interface{}{
				"name":         t.Name,
				"description":  t.Description,
				"input_schema": t.InputSchema,
			}
		}
		body["tools"] = tools
	}

	reqBytes, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	invokeInput := &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(a.model),
		Body:        reqBytes,
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
	}

	start := time.Now()
	var output *bedrockruntime.InvokeModelOutput
	if a.invokeFunc != nil {
		output, err = a.invokeFunc(callCtx, invokeInput)
	} else {
		output, err = a.client.InvokeModel(callCtx, invokeInput)
	}
	elapsed := time.Since(start)
	durationMs := int(elapsed.Milliseconds())
	// Record the latency for observability regardless of success/failure —
	// tail-latency alerts need to see degrading providers before they start
	// erroring. Fires only when an observer is attached (nil-safe).
	a.RecordJudgeLatency(a.model, elapsed)
	if err != nil {
		a.RecordFailure()
		return Response{DurationMs: durationMs}, fmt.Errorf("bedrock invoke failed: %w", err)
	}

	resp, parseErr := parseAnthropicResponse(output.Body)
	if parseErr != nil {
		a.RecordFailure()
		resp.DurationMs = durationMs
		return resp, parseErr
	}

	a.RecordSuccess()
	resp.DurationMs = durationMs
	return resp, nil
}

// StripCodeFences removes optional markdown code fences (```json ... ``` or ``` ... ```)
// that some models wrap around their JSON output.
func StripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		idx := strings.Index(s, "\n")
		if idx == -1 {
			return s
		}
		s = s[idx+1:]
		if end := strings.LastIndex(s, "```"); end != -1 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}
	return s
}
