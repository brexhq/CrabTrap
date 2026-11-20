package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brexhq/CrabTrap/internal/admin"
	"github.com/brexhq/CrabTrap/internal/approval"
	"github.com/brexhq/CrabTrap/internal/db"
	"github.com/brexhq/CrabTrap/internal/dbtest"
	"github.com/brexhq/CrabTrap/internal/eval"
	"github.com/brexhq/CrabTrap/pkg/types"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	pool, cleanup, err := dbtest.Setup()
	if err != nil {
		slog.Error("proxy TestMain", "error", err)
		os.Exit(1)
	}
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// truncateTestTables wipes all tables between tests.
// TRUNCATE llm_policies CASCADE covers: users (via llm_policy_id FK), user_channels,
// approval_requests, approval_cache, and audit_log.
func truncateTestTables(t *testing.T) {
	t.Helper()
	testPool.Exec(context.Background(), "TRUNCATE llm_policies CASCADE")
}

// newTestManager returns a Manager with all tables truncated.
func newTestManager(t *testing.T) *approval.Manager {
	t.Helper()
	truncateTestTables(t)
	return approval.NewManager()
}

// newPGAuditReader returns a PGAuditReader backed by testPool.
func newPGAuditReader() *admin.PGAuditReader {
	return admin.NewPGAuditReader(testPool)
}

// newPGEvalStore returns a PGStore backed by testPool (used as LLMResponseWriter).
func newPGEvalStore() *eval.PGStore {
	return eval.NewPGStore(testPool)
}

// seedLLMPolicy inserts an llm_policies row and returns its ID.
func seedLLMPolicy(t *testing.T, name, prompt, provider, model string) string {
	t.Helper()
	id := db.NewID("llmpol")
	_, err := testPool.Exec(context.Background(), `
		INSERT INTO llm_policies(id, name, prompt, provider, model)
		VALUES($1, $2, $3, $4, $5)
	`, id, name, prompt, provider, model)
	if err != nil {
		t.Fatalf("seedLLMPolicy(%q): %v", name, err)
	}
	return id
}

// seedLLMPolicyWithRules inserts an llm_policies row with static rules and returns its ID.
func seedLLMPolicyWithRules(t *testing.T, name, prompt string, rules []types.StaticRule) string {
	t.Helper()
	id := db.NewID("llmpol")
	rulesJSON, _ := json.Marshal(rules)
	_, err := testPool.Exec(context.Background(), `
		INSERT INTO llm_policies(id, name, prompt, provider, model, static_rules)
		VALUES($1, $2, $3, '', '', $4)
	`, id, name, prompt, rulesJSON)
	if err != nil {
		t.Fatalf("seedLLMPolicyWithRules(%q): %v", name, err)
	}
	return id
}

// seedUser upserts a user, creating and linking an llm_policy when policyPrompt is non-empty.
// Returns the llm_policy_id that was created (empty string if policyPrompt was empty).
func seedUser(t *testing.T, userID, policyPrompt string) string {
	t.Helper()
	if userID == "" {
		return ""
	}
	ctx := context.Background()
	var policyID *string
	var policyIDStr string
	if policyPrompt != "" {
		id := seedLLMPolicy(t, "policy-for-"+userID, policyPrompt, "", "")
		policyID = &id
		policyIDStr = id
	}
	_, err := testPool.Exec(ctx, `
		INSERT INTO users(id, llm_policy_id) VALUES($1, $2)
		ON CONFLICT(id) DO UPDATE SET llm_policy_id = EXCLUDED.llm_policy_id
	`, userID, policyID)
	if err != nil {
		t.Fatalf("seedUser(%q): %v", userID, err)
	}
	return policyIDStr
}

// ensureUser inserts a user row so FK constraints are satisfied (no policy_prompt update).
func ensureUser(t *testing.T, userID string) {
	t.Helper()
	if err := dbtest.EnsureUser(context.Background(), testPool, userID); err != nil {
		t.Fatalf("ensureUser(%q): %v", userID, err)
	}
}

// testLoopbackCIDRs returns allowed CIDRs that permit connections to loopback
// and all RFC 1918 addresses, used by tests whose backends run on 127.0.0.1.
func testLoopbackCIDRs() []*net.IPNet {
	cidrs := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"}
	var nets []*net.IPNet
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return nets
}

// seedGatewayAuthChannel inserts a gateway_auth channel for the given user and returns the token.
// The user must already exist (use ensureUser/seedUser first).
func seedGatewayAuthChannel(t *testing.T, userID string) string {
	t.Helper()
	ctx := context.Background()
	gatToken := db.NewGatewayAuthToken()
	chanID := db.NewID("chan")
	payload, _ := json.Marshal(map[string]string{"gateway_auth_token": admin.TokenHash(gatToken)})
	_, err := testPool.Exec(ctx, `
		INSERT INTO user_channels(id, user_id, channel_type, payload)
		VALUES($1, $2, 'gateway_auth', $3)
		ON CONFLICT(user_id, channel_type) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()
	`, chanID, userID, payload)
	if err != nil {
		t.Fatalf("seedGatewayAuthChannel(%q): %v", userID, err)
	}
	return gatToken
}

