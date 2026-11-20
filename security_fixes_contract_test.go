// Package fixturessim holds one contract test for 14 security fixes.
//
// Each subtest pins the code that implements one fix: reverting that fix turns
// exactly that subtest red. Assertions read parsed Go sources (comments
// stripped, so a stale comment cannot satisfy them), packaging YAML, and
// container build files. No database, network, Docker, or fixed port.
//
// This is deliberately the only test added by the patch: shape, not behaviour.
// Fix 10 (eval count) is log-only, so shape is all there is to pin.
package fixturessim

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func raw(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// code returns path parsed and printed without comments.
func code(t *testing.T, path string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	f.Comments = nil
	var b strings.Builder
	if err := (&printer.Config{Mode: printer.RawFormat}).Fprint(&b, fset, f); err != nil {
		t.Fatalf("print %s: %v", path, err)
	}
	return b.String()
}

// decl returns one function or method (by name) from path, without comments.
func decl(t *testing.T, path, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out string
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != name || out != "" {
			return out == ""
		}
		var b strings.Builder
		(&printer.Config{Mode: printer.RawFormat}).Fprint(&b, fset, fd)
		out = b.String()
		return false
	})
	if out == "" {
		t.Fatalf("%s: no declaration of %s", path, name)
	}
	return out
}

// needs reports every needle missing from got.
func needs(got string, needles ...string) (missing []string) {
	for _, n := range needles {
		if !strings.Contains(got, n) {
			missing = append(missing, n)
		}
	}
	return missing
}

func wantAll(t *testing.T, label, got string, needles ...string) {
	t.Helper()
	if miss := needs(got, needles...); len(miss) > 0 {
		t.Errorf("%s: missing %q", label, miss)
	}
}

// fix 1: tokens are stored and looked up as sha256 only, never echoed back.
func TestFix01TokenHashOnly(t *testing.T) {
	store := code(t, "internal/admin/pg_user_store.go")
	wantAll(t, "fix1 TokenHash", decl(t, "internal/admin/pg_user_store.go", "TokenHash"), "sha256.Sum256(")
	wantAll(t, "fix1 user payload", store, "tokenPayload(")
	if strings.Contains(store, `p["web_token"]`) || strings.Contains(store, `p["gateway_auth_token"]`) {
		t.Error("fix1: plaintext token still decoded into the user response DTO")
	}
	sql := raw(t, "internal/db/migrations/005_hash_legacy_tokens.sql")
	wantAll(t, "fix1 migration", sql, "web_token", "gateway_auth_token", "sha256(")
	if strings.Count(sql, "sha256(") < 2 {
		t.Error("fix1: migration must hash both stored token keys")
	}

	// The edit form always submits web_token/gateway_auth_token, empty when the
	// token is not shown back. Empty must be a no-op; deleting needs a flag.
	wantAll(t, "fix1 clear flags", store,
		"clear_web_token", "clear_gateway_auth_token", "ClearWebToken", "ClearGatewayAuthToken")
	upd := decl(t, "internal/admin/pg_user_store.go", "UpdateUser")
	for _, c := range []struct{ empty, flag, channel string }{
		{`*req.WebToken == ""`, "req.ClearWebToken", "'web'"},
		{`*req.GatewayAuthToken == ""`, "req.ClearGatewayAuthToken", "'gateway_auth'"},
	} {
		e := strings.Index(upd, c.empty)
		f := strings.Index(upd, c.flag)
		d := strings.Index(upd, "DELETE FROM user_channels WHERE user_id = $1 AND channel_type = "+c.channel)
		if e < 0 || f < 0 || d < 0 || !(e < f && f < d) {
			t.Errorf("fix1: %s delete is not behind empty check %q and flag %q", c.channel, c.empty, c.flag)
		}
	}
}

// fix 2: a client that cannot keep up is disconnected, not fed forever.
func TestFix02SSEDisconnectsSlowClient(t *testing.T) {
	deliver := decl(t, "internal/notifications/sse.go", "deliver")
	wantAll(t, "fix2 deliver", deliver, "default:", "closeDone()")
}

// fix 3: admin/UI listens on loopback unless the container opts out.
func TestFix03AdminLoopbackDefault(t *testing.T) {
	cfg := code(t, "internal/config/config.go")
	wantAll(t, "fix3 config", cfg, "Admin.Listen", `os.Getenv("ADMIN_LISTEN")`)
	m := regexp.MustCompile(`Admin\.Listen = "([^"]+)"`).FindStringSubmatch(cfg)
	if m == nil {
		t.Fatal("fix3: no default for Admin.Listen")
	}
	host, _, err := net.SplitHostPort(m[1])
	if err != nil {
		t.Fatalf("fix3: Admin.Listen default %q is not host:port: %v", m[1], err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Errorf("fix3: Admin.Listen default %q is not loopback", m[1])
	}

	var compose struct {
		Services map[string]struct {
			Ports       []string          `yaml:"ports"`
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(raw(t, "docker-compose.yml")), &compose); err != nil {
		t.Fatalf("fix3: docker-compose.yml: %v", err)
	}
	published, optedOut := false, false
	for _, svc := range compose.Services {
		if svc.Environment["ADMIN_LISTEN"] == "0.0.0.0:8081" {
			optedOut = true
		}
		for _, p := range svc.Ports {
			parts := strings.Split(p, ":")
			if len(parts) != 3 || parts[2] != "8081" {
				continue
			}
			if ip := net.ParseIP(parts[0]); ip != nil && ip.IsLoopback() {
				published = true
			}
		}
	}
	if !published {
		t.Error("fix3: docker-compose.yml does not publish admin port 8081 on host loopback")
	}
	if !optedOut {
		t.Error("fix3: docker-compose.yml does not set ADMIN_LISTEN=0.0.0.0:8081 for the container")
	}
}

// fix 4: the per-IP limiter cache is bounded and keeps state across eviction.
func TestFix04RateLimiterBounded(t *testing.T) {
	wantAll(t, "fix4 lru", code(t, "internal/proxy/lru.go"), "evictOldest", "GetOrCreateWithEvict(")
	wantAll(t, "fix4 ratelimit", code(t, "internal/proxy/ratelimit.go"), "maxCachedLimiters", "GetOrCreateWithEvict(", "pruneEvicted")
}

// fix 5: a response body copy that fails aborts the connection instead of
// framing a truncated body as complete.
func TestFix05CopyErrorAborts(t *testing.T) {
	src := raw(t, "internal/proxy/handler.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "handler.go", src, 0)
	if err != nil {
		t.Fatalf("fix5: parse handler.go: %v", err)
	}
	var stack []ast.Node
	unchecked := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok || len(stack) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Copy" || len(call.Args) < 2 {
			return true
		}
		if body, ok := call.Args[1].(*ast.SelectorExpr); !ok || body.Sel.Name != "Body" {
			return true
		} else if id, ok := body.X.(*ast.Ident); !ok || id.Name != "resp" {
			return true
		}
		if _, assigned := stack[len(stack)-2].(*ast.AssignStmt); !assigned {
			unchecked++
		}
		return true
	})
	if unchecked > 0 {
		t.Errorf("fix5: %d io.Copy call(s) discard their error", unchecked)
	}
	wantAll(t, "fix5 abort", code(t, "internal/proxy/handler.go"), "ErrAbortHandler")
}

// fix 6: the UI is read from web/dist next to the executable, not embedded.
func TestFix06WebDistFromDisk(t *testing.T) {
	src := raw(t, "cmd/gateway/web_handler.go")
	wantAll(t, "fix6 exe dir", code(t, "cmd/gateway/web_handler.go"), "os.Executable()")
	if strings.Contains(src, "go:embed web/dist") {
		t.Error("fix6: UI is embedded again, so a published web/dist cannot be served")
	}
}

// fix 7: every TLS handshake (upstream and MITM) is bounded by a timeout.
func TestFix07TLSHandshakeBounded(t *testing.T) {
	src := code(t, "internal/proxy/handler.go")
	if n := strings.Count(src, "HandshakeContext("); n < 2 {
		t.Errorf("fix7: %d bounded handshake(s), want the upstream and the MITM handshake", n)
	}
	wantAll(t, "fix7 timeout", src, "tlsHandshakeTimeout")
}

// fix 8: a full audit insert queue drops the record with a counted warning
// instead of blocking the request path.
func TestFix08AuditInsertNonBlocking(t *testing.T) {
	wantAll(t, "fix8 Add", decl(t, "internal/admin/pg_audit_reader.go", "Add"),
		"insertSem", `"PGAuditReader.Add: insert queue full, audit record dropped"`)
	wantAll(t, "fix8 counter", code(t, "internal/admin/pg_audit_reader.go"), "droppedInserts")
}

// fix 9: an SSE policy result reports a failed persist instead of claiming ok.
func TestFix09PolicyPersistError(t *testing.T) {
	wantAll(t, "fix9", code(t, "internal/admin/api.go"), `"persist_error"`)
}

// fix 10: an eval run survives a failed audit count (no false success).
func TestFix10EvalCountTolerated(t *testing.T) {
	wantAll(t, "fix10", code(t, "internal/admin/api.go"), "failed to count audit entries for eval run")
}

// fix 11: identical judge requests reuse a bounded decision cache, cache hits
// persist no duplicate llm_responses row, and prompt previews are quoted.
func TestFix11DecisionCache(t *testing.T) {
	wantAll(t, "fix11 cache", decl(t, "internal/approval/manager.go", "SetDecisionCache"), "decisionCache")
	wantAll(t, "fix11 wiring", code(t, "cmd/gateway/main.go"), "SetDecisionCache(cfg.Approval.CacheTTL")
	wantAll(t, "fix11 handler", code(t, "internal/proxy/handler.go"), `decision.ApprovedBy == "cache"`)
	wantAll(t, "fix11 judge", code(t, "internal/judge/llm_judge.go"), "strconv.Quote(")
}

// fix 12: one sensitive-header list, used by both the debug log and the
// persisted audit log, so redaction cannot drift between them.
func TestFix12SensitiveHeaderSingleSource(t *testing.T) {
	shared := decl(t, "pkg/types/types.go", "IsSensitiveHeader")
	wantAll(t, "fix12 list", shared, `"Authorization"`, `"X-Vault-Token"`, `"Proxy-Authorization"`)
	if strings.Contains(code(t, "internal/proxy/handler.go"), "func isSensitiveHeader(") {
		t.Error("fix12: proxy kept a private sensitive-header list")
	}
	wantAll(t, "fix12 proxy", code(t, "internal/proxy/handler.go"), "types.IsSensitiveHeader(")
	wantAll(t, "fix12 audit", code(t, "internal/admin/pg_audit_reader.go"), "types.IsSensitiveHeader(")
}

// fix 13: stacked Content-Encoding layers share one decompression budget, and
// a body the judge cannot fully read is marked instead of silently truncated.
func TestFix13StackedDecompressionBudget(t *testing.T) {
	wantAll(t, "fix13 layer", decl(t, "internal/proxy/handler.go", "decompressSingleLayer"), "budget int64")
	src := code(t, "internal/proxy/handler.go")
	wantAll(t, "fix13 budget", src, "budgetMarker", "totalBudget", "[]byte(budgetMarker)")
	wantAll(t, "fix13 truncation", src, "truncatedMarker")
}

// dockerignorePatterns lists the non-comment patterns of a .dockerignore.
func dockerignorePatterns(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(raw(t, path), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.TrimPrefix(line, "/"))
	}
	return out
}

// fix 14: releases ship the built UI next to the binary and inside the image.
func TestFix14ReleaseShipsWebDist(t *testing.T) {
	wantAll(t, "fix14 dockerfile", raw(t, "Dockerfile.goreleaser"), "COPY web/dist")
	for _, p := range dockerignorePatterns(t, ".dockerignore") {
		if strings.HasPrefix(p, "web/dist") {
			t.Errorf("fix14: .dockerignore keeps %s out of the image build context", p)
		}
	}

	var goreleaser struct {
		Archives []struct {
			Files []struct {
				Src string `yaml:"src"`
			} `yaml:"files"`
		} `yaml:"archives"`
		DockersV2 []struct {
			ExtraFiles []string `yaml:"extra_files"`
		} `yaml:"dockers_v2"`
	}
	if err := yaml.Unmarshal([]byte(raw(t, ".goreleaser.yaml")), &goreleaser); err != nil {
		t.Fatalf("fix14: .goreleaser.yaml: %v", err)
	}
	archiveOK := false
	for _, a := range goreleaser.Archives {
		for _, f := range a.Files {
			archiveOK = archiveOK || strings.HasPrefix(f.Src, "web/dist")
		}
	}
	if !archiveOK {
		t.Error("fix14: release archives do not include web/dist")
	}
	imageOK := false
	for _, d := range goreleaser.DockersV2 {
		for _, p := range d.ExtraFiles {
			imageOK = imageOK || strings.HasPrefix(p, "web/dist")
		}
	}
	if !imageOK {
		t.Error("fix14: docker image does not get web/dist")
	}

	for _, wf := range []string{".github/workflows/ci.yml", ".github/workflows/release.yml"} {
		src := raw(t, wf)
		if strings.Contains(src, "build-web-for-dev") || strings.Contains(src, "cmd/gateway/web") {
			t.Errorf("fix14: %s still stages the UI for embedding", wf)
		}
	}
}
