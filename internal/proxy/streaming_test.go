package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/approval"
	"github.com/brexhq/CrabTrap/internal/audit"
	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/pkg/types"
)

const largeBodySize = maxBufferedBodySize + 1024*1024 // 11 MB — exceeds the 10 MB cap

// makeLargeBody returns size bytes filled with a repeating alphabetic pattern.
func makeLargeBody(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte('A' + (i % 26))
	}
	return b
}

// newStreamingTestHandler builds a Handler with passthrough approval and no credential manager.
// It truncates test tables as a side effect (via newTestManager).
func newStreamingTestHandler(t *testing.T, auditFile string) *Handler {
	t.Helper()
	mgr := newTestManager(t)
	mgr.SetMode("passthrough")
	auditLogger, err := audit.NewLogger(auditFile)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { auditLogger.Close() })
	h := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), nil, true)
	// Test backends run on 127.0.0.1; allow loopback so the SSRF
	// filter does not block connections to loopback test servers.
	h.allowedPrivateCIDRs = testLoopbackCIDRs()
	h.initClient()
	return h
}

// TestLargeResponseIsStreamed verifies that processRequest returns before the backend has
// finished sending the full body — i.e., the response is streamed, not fully buffered.
//
// The backend sends exactly maxBufferedBodySize+1 bytes (enough to trigger the cap), then
// blocks. The test asserts that processRequest returns while the backend is still blocked.
// Only after that does it unblock the backend to send a sentinel tail, then verifies the
// full body (prefix + tail) is readable from resp.Body.
func TestLargeResponseIsStreamed(t *testing.T) {
	first := makeLargeBody(maxBufferedBodySize + 1) // exactly enough to trigger the cap
	tail := []byte("streaming-tail-sentinel")
	unblock := make(chan struct{})
	defer func() {
		// Ensure the backend goroutine is unblocked on early test exit (e.g. timeout).
		select {
		case <-unblock:
		default:
			close(unblock)
		}
	}()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(first)
		w.(http.Flusher).Flush() // push bytes to the proxy before blocking
		<-unblock                // block here — tail not sent yet
		w.Write(tail)
	}))
	defer backend.Close()

	handler := newStreamingTestHandler(t, filepath.Join(t.TempDir(), "audit.jsonl"))

	respCh := make(chan *http.Response, 1)
	go func() {
		req, _ := http.NewRequest("GET", backend.URL+"/stream", nil)
		req.URL.Scheme = "http"
		respCh <- handler.processRequest(req, "req_stream_verify", time.Now(), context.Background())
	}()

	// processRequest must return while the backend is still blocked on <-unblock.
	// If it were buffering the full body it would block here until the backend finishes,
	// which would cause the 10-second timeout below to fire.
	select {
	case resp := <-respCh:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		// Now unblock the backend so it sends the tail.
		close(unblock)
		received, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		if len(received) != len(first)+len(tail) {
			t.Errorf("received %d bytes, want %d", len(received), len(first)+len(tail))
		}
		if !bytes.Equal(received[len(first):], tail) {
			t.Errorf("tail mismatch: got %q, want %q", received[len(first):], tail)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("processRequest blocked waiting for full body — body is being fully buffered instead of streamed")
	}
}

// TestLargeResponseAuditTruncation verifies that the audit log entry written to
// file does not contain the response body (sensitive payload is stripped from
// file/stdout output).
func TestLargeResponseAuditTruncation(t *testing.T) {
	data := makeLargeBody(largeBodySize)
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer backend.Close()

	handler := newStreamingTestHandler(t, auditFile)

	req, _ := http.NewRequest("GET", backend.URL+"/large", nil)
	req.URL.Scheme = "http"

	resp := handler.processRequest(req, "req_stream_audit", time.Now(), context.Background())
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	entries := readAuditEntries(t, auditFile)
	if len(entries) == 0 {
		t.Fatal("no audit entries written")
	}
	e := entries[len(entries)-1]
	// File/stdout audit output strips response bodies to avoid logging sensitive data.
	if e.ResponseBody != "" {
		t.Errorf("expected empty ResponseBody in file audit output, got %d bytes", len(e.ResponseBody))
	}
}

// TestSmallResponseFullyBuffered verifies that responses under maxBufferedBodySize
// are fully delivered to the client. The file audit output strips the response body
// to avoid logging sensitive payload data.
func TestSmallResponseFullyBuffered(t *testing.T) {
	data := []byte(`{"message":"small response ok"}`)
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer backend.Close()

	handler := newStreamingTestHandler(t, auditFile)

	req, _ := http.NewRequest("GET", backend.URL+"/small", nil)
	req.URL.Scheme = "http"

	resp := handler.processRequest(req, "req_small_resp", time.Now(), context.Background())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	received, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if !bytes.Equal(received, data) {
		t.Errorf("got %q, want %q", received, data)
	}

	entries := readAuditEntries(t, auditFile)
	if len(entries) == 0 {
		t.Fatal("no audit entries written")
	}
	e := entries[len(entries)-1]
	// File/stdout audit output strips response bodies to avoid logging sensitive data.
	if e.ResponseBody != "" {
		t.Errorf("expected empty ResponseBody in file audit output, got %q", e.ResponseBody)
	}
}

// TestLargeUploadReachesUpstream verifies that request bodies exceeding maxBufferedBodySize
// are fully forwarded to the upstream server.
func TestLargeUploadReachesUpstream(t *testing.T) {
	uploadData := makeLargeBody(largeBodySize)

	var receivedSize int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("body read error: %v", err), http.StatusInternalServerError)
			return
		}
		receivedSize = len(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler := newStreamingTestHandler(t, filepath.Join(t.TempDir(), "audit.jsonl"))

	req, _ := http.NewRequest("POST", backend.URL+"/upload", bytes.NewReader(uploadData))
	req.URL.Scheme = "http"
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(largeBodySize)

	resp := handler.processRequest(req, "req_large_upload", time.Now(), context.Background())
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	// receivedSize is set by the backend before it sends its response, so by the time
	// processRequest returns the value is already populated.
	if receivedSize != largeBodySize {
		t.Errorf("upstream received %d bytes, want %d", receivedSize, largeBodySize)
	}
}

type gatedTailReader struct {
	data                 []byte
	release              <-chan struct{}
	upstreamStarted      *atomic.Bool
	readBeforeUpstreamCh chan<- struct{}
	pos                  int
}

func (r *gatedTailReader) Read(p []byte) (int, error) {
	if !r.upstreamStarted.Load() {
		select {
		case r.readBeforeUpstreamCh <- struct{}{}:
		default:
		}
	}
	<-r.release
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// TestLargeUploadLLMStaticRuleDoesNotDrainStreamingTail verifies that LLM-mode
// approval uses the proxy's buffered request prefix instead of reading the full
// streaming body before forwarding. Static rules are checked before the judge,
// so approval should complete without consuming the unread tail of a large body.
func TestLargeUploadLLMStaticRuleDoesNotDrainStreamingTail(t *testing.T) {
	prefix := makeLargeBody(maxBufferedBodySize + 1)
	tailData := []byte("tail-after-buffer-limit")
	releaseTail := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseTail) })

	var upstreamStarted atomic.Bool
	readBeforeUpstream := make(chan struct{}, 1)
	tail := &gatedTailReader{
		data:                 tailData,
		release:              releaseTail,
		upstreamStarted:      &upstreamStarted,
		readBeforeUpstreamCh: readBeforeUpstream,
	}

	upstreamReached := make(chan struct{})
	upstreamReceived := make(chan int64, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted.Store(true)
		close(upstreamReached)
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("body read error: %v", err), http.StatusInternalServerError)
			return
		}
		upstreamReceived <- n
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	adapterCalled := make(chan struct{}, 1)
	mgr := approval.NewManager()
	mgr.SetJudge(judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		select {
		case adapterCalled <- struct{}{}:
		default:
		}
		return llm.Response{Text: `{"decision":"ALLOW","reason":"fallback"}`}, nil
	}}), "llm", "deny")

	auditLogger, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	defer auditLogger.Close()

	handler := NewHandler(nil, mgr, auditLogger, nil, nil, true)
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()

	policy := &types.LLMPolicy{
		ID:     "llmpol_large_upload_static",
		Name:   "large upload static allow",
		Prompt: "deny everything unless a static rule allows it",
		StaticRules: []types.StaticRule{{
			Methods:    []string{http.MethodPost},
			URLPattern: backend.URL + "/",
			MatchType:  "prefix",
			Action:     "allow",
		}},
	}
	ctx := context.WithValue(context.Background(), approval.ContextKeyLLMPolicy, policy)

	body := io.NopCloser(io.MultiReader(bytes.NewReader(prefix), tail))
	req, err := http.NewRequest(http.MethodPost, backend.URL+"/upload", body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.ContentLength = int64(len(prefix) + len(tailData))
	req.Header.Set("Content-Type", "application/octet-stream")

	respCh := make(chan *http.Response, 1)
	go func() {
		respCh <- handler.processRequest(req, "req_large_llm_static", time.Now(), ctx)
	}()

	select {
	case <-upstreamReached:
		// Good: approval completed and forwarding began without draining tail.
	case <-readBeforeUpstream:
		releaseOnce.Do(func() { close(releaseTail) })
		t.Fatal("approval read the streaming tail before the request reached upstream")
	case <-time.After(2 * time.Second):
		releaseOnce.Do(func() { close(releaseTail) })
		t.Fatal("request did not reach upstream; approval may be blocked reading the body")
	}

	releaseOnce.Do(func() { close(releaseTail) })

	resp := <-respCh
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	if got := <-upstreamReceived; got != int64(len(prefix)+len(tailData)) {
		t.Fatalf("upstream received %d bytes, want %d", got, len(prefix)+len(tailData))
	}

	select {
	case <-adapterCalled:
		t.Fatal("static allow rule should bypass the LLM judge")
	default:
	}
}
