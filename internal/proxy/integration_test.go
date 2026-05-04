package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/admin"
	"github.com/brexhq/CrabTrap/internal/audit"
	"github.com/brexhq/CrabTrap/internal/config"
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// getTestConfig returns a config with proper certificate paths for testing.
// Uses port 19080 to avoid conflicting with the dev server on 8080.
func getTestConfig() *config.Config {
	cfg := config.Default()
	cfg.Proxy.Port = 19080
	cfg.Approval.Mode = "passthrough"
	cfg.TLS.CACertPath = "../../certs/ca.crt"
	cfg.TLS.CAKeyPath = "../../certs/ca.key"
	// Test backends run on 127.0.0.1; allow loopback and private ranges so the
	// SSRF filter does not block connections to loopback test servers.
	cfg.Proxy.AllowedPrivateCIDRs = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"}
	cfg.Proxy.InsecureSkipUpstreamVerify = true // test backends use self-signed certs
	return cfg
}

// newTestServer creates a proxy Server with PG-backed approval components for tests.
func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	mgr := newTestManager(t)
	mgr.SetMode(cfg.Approval.Mode)
	s, err := NewServer(cfg, nil, mgr, nil)
	if err != nil {
		t.Fatalf("Failed to create proxy server: %v", err)
	}
	return s
}

// TestEndToEndReadOperation tests that GET requests pass through immediately
func TestEndToEndReadOperation(t *testing.T) {
	// Setup backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Hello from backend",
			"method":  r.Method,
		})
	}))
	defer backendServer.Close()

	// Setup proxy
	cfg := getTestConfig()
	proxyServer := newTestServer(t, cfg)

	// Start proxy in background
	go func() {
		proxyServer.Start()
	}()
	defer proxyServer.Shutdown(context.Background())

	time.Sleep(100 * time.Millisecond) // Wait for proxy to start

	// Create HTTP client configured to use proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(fmt.Sprintf("http://localhost:%d", cfg.Proxy.Port))),
		},
		Timeout: 5 * time.Second,
	}

	// Make GET request
	resp, err := client.Get(backendServer.URL + "/api/users")
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result["method"] != "GET" {
		t.Errorf("Expected method GET, got %s", result["method"])
	}
}

// TestEndToEndUnmanagedWritePassThrough verifies that in passthrough mode,
// write requests that do not use CrabTrap-managed credentials are allowed
// through without approval.
func TestEndToEndUnmanagedWritePassThrough(t *testing.T) {
	const testUserID = "unmanaged-pass-through@example.com"

	backendCalled := false
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "ok",
			"method":  r.Method,
		})
	}))
	defer backendServer.Close()

	mgr := newTestManager(t)
	mgr.SetMode("passthrough")
	ensureUser(t, testUserID)
	gatToken := seedGatewayAuthChannel(t, testUserID)

	auditLogger, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	defer auditLogger.Close()

	handler := NewHandler(nil, mgr, auditLogger, newPGAuditReader(), admin.NewPGUserStore(testPool), true)
	// Test backends run on 127.0.0.1; allow private networks so the SSRF
	// filter does not block connections to loopback test servers.
	handler.allowedPrivateCIDRs = testLoopbackCIDRs()
	handler.initClient()
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	proxyURL.User = url.UserPassword(gatToken, "")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	req, err := http.NewRequest(http.MethodPost, backendServer.URL+"/api/unmanaged", bytes.NewBufferString(`{"x":1}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !backendCalled {
		t.Fatal("backend was not called")
	}
}

// TestEndToEndWritePassthrough tests POST request in passthrough mode
func TestEndToEndWritePassthrough(t *testing.T) {
	backendCalled := false
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "Created",
			"method":        r.Method,
			"received_body": string(body),
		})
	}))
	defer backendServer.Close()

	cfg := getTestConfig()
	proxyServer := newTestServer(t, cfg)

	go func() {
		proxyServer.Start()
	}()
	defer proxyServer.Shutdown(context.Background())

	time.Sleep(200 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(fmt.Sprintf("http://localhost:%d", cfg.Proxy.Port))),
		},
		Timeout: 15 * time.Second,
	}

	reqBody := bytes.NewBufferString(`{"name":"John","email":"john@example.com"}`)
	postResp, postErr := client.Post(backendServer.URL+"/api/users", "application/json", reqBody)
	if postErr != nil {
		t.Fatalf("POST request failed: %v", postErr)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", postResp.StatusCode)
	}

	if !backendCalled {
		t.Error("Backend was not called")
	}

	var result map[string]interface{}
	json.NewDecoder(postResp.Body).Decode(&result)

	if result["method"] != "POST" {
		t.Errorf("Expected method POST, got %s", result["method"])
	}
}
// TestEndToEndHTTPSRequest tests HTTPS CONNECT tunneling
func TestEndToEndHTTPSRequest(t *testing.T) {
	// Setup HTTPS backend server
	backendServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Hello from HTTPS backend",
			"method":  r.Method,
			"scheme":  "https",
		})
	}))
	defer backendServer.Close()

	// Setup proxy
	cfg := getTestConfig()
	proxyServer := newTestServer(t, cfg)

	// Start proxy in background
	go func() {
		proxyServer.Start()
	}()
	defer proxyServer.Shutdown(context.Background())

	time.Sleep(100 * time.Millisecond) // Wait for proxy to start

	// Create HTTP client configured to use proxy with HTTPS support
	// For testing, we skip TLS verification since httptest creates self-signed certs
	proxyURL := mustParseURL(fmt.Sprintf("http://localhost:%d", cfg.Proxy.Port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // OK for testing
			},
		},
		Timeout: 5 * time.Second,
	}

	// Make GET request to HTTPS backend
	resp, err := client.Get(backendServer.URL + "/api/secure")
	if err != nil {
		t.Fatalf("HTTPS GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result["method"] != "GET" {
		t.Errorf("Expected method GET, got %s", result["method"])
	}

	if result["scheme"] != "https" {
		t.Errorf("Expected scheme https, got %s", result["scheme"])
	}
}

// TestHTTPS_RejectsUntrustedUpstream verifies that when
// InsecureSkipUpstreamVerify is false (the default), the proxy rejects
// upstream servers with self-signed / untrusted TLS certificates.
func TestHTTPS_RejectsUntrustedUpstream(t *testing.T) {
	backendServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backendServer.Close()

	cfg := getTestConfig()
	cfg.Proxy.InsecureSkipUpstreamVerify = false // enforce TLS verification
	proxyServer := newTestServer(t, cfg)

	go func() { proxyServer.Start() }()
	defer proxyServer.Shutdown(context.Background())
	time.Sleep(100 * time.Millisecond)

	proxyURL := mustParseURL(fmt.Sprintf("http://localhost:%d", cfg.Proxy.Port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // client trusts proxy; proxy should not trust backend
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(backendServer.URL + "/test")
	if err != nil {
		// Connection error is acceptable — the proxy refused the upstream.
		return
	}
	defer resp.Body.Close()

	// If we got a response, it should be 502 Bad Gateway (proxy failed to
	// connect upstream due to TLS error).
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway when upstream cert is untrusted, got %d", resp.StatusCode)
	}
}

func mustParseURL(urlStr string) *url.URL {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}
	return u
}

// readAuditEntries reads all JSON-line audit entries from a file.
func readAuditEntries(t *testing.T, path string) []types.AuditEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entries []types.AuditEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e types.AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse audit entry %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

// newAdminServer wires up just the admin API (no proxy) backed by PG components.
const integrationAdminToken = "integration-test-admin-token"

// integrationAdminValidator is a minimal WebTokenValidator for integration tests.
type integrationAdminValidator struct{}

func (v *integrationAdminValidator) GetUserByWebToken(token string) (string, string, bool) {
	if token == integrationAdminToken {
		return "test-admin@example.com", "admin", true
	}
	return "", "", false
}

// adminGet makes an authenticated GET request to the admin API.
func adminGet(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+integrationAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func newAdminServer(t *testing.T) *httptest.Server {
	t.Helper()
	truncateTestTables(t)
	api := admin.NewAPI(newPGAuditReader(), nil, notifications.NewSSEChannel("web"), &integrationAdminValidator{}, nil)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestEmptyAuditLogReturnsArray verifies the entries field in the audit response is [] not null.
func TestEmptyAuditLogReturnsArray(t *testing.T) {
	srv := newAdminServer(t)

	resp := adminGet(t, srv, "/admin/audit")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result map[string]json.RawMessage
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parse /admin/audit response: %v", err)
	}
	entries := result["entries"]
	if string(entries) == "null" {
		t.Error("audit entries: got null, want []")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(entries, &arr); err != nil {
		t.Errorf("audit entries is not a JSON array: %s", entries)
	}
}

