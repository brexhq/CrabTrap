package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brexhq/CrabTrap/internal/admin"
	"github.com/brexhq/CrabTrap/internal/llmpolicy"
	"github.com/brexhq/CrabTrap/internal/notifications"
)

const testAdminToken = "test-admin-token"

// testTokenValidator authenticates testAdminToken as an admin, all others fail.
type testTokenValidator struct{}

func (v *testTokenValidator) GetUserByWebToken(token string) (string, string, bool) {
	if token == testAdminToken {
		return "admin@test.com", "admin", true
	}
	return "", "", false
}

// adminTestEnv holds the mux ready for httptest requests.
type adminTestEnv struct {
	mux *http.ServeMux
}

// setupAdminAPI builds the real admin.API (same wiring as startAdminAPI) against
// the test database and returns the mux ready for httptest requests.
func setupAdminAPI(t *testing.T) adminTestEnv {
	t.Helper()
	testPool.Exec(context.Background(), "TRUNCATE audit_log, llm_policies CASCADE")

	auditReader := admin.NewPGAuditReader(testPool)
	userStore := admin.NewPGUserStore(testPool)
	policyStore := llmpolicy.NewPGStore(testPool)
	dispatcher := notifications.NewDispatcher()
	sseChannel := notifications.NewSSEChannel("web")

	api := admin.NewAPI(auditReader, dispatcher, sseChannel, &testTokenValidator{}, userStore)
	api.SetLLMPolicyStore(policyStore)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	return adminTestEnv{mux: mux}
}

// adminReq fires an authenticated request against the test mux.
func adminReq(t *testing.T, env adminTestEnv, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, req)
	return w
}

// ---- Health ----

func TestHealthEndpoint(t *testing.T) {
	env := setupAdminAPI(t)
	w := adminReq(t, env, http.MethodGet, "/admin/health", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status: got %v", resp["status"])
	}
}

// ---- LLM Policies ----

func TestLLMPolicies_ListEmpty(t *testing.T) {
	env := setupAdminAPI(t)
	w := adminReq(t, env, http.MethodGet, "/admin/llm-policies", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var policies []interface{}
	json.NewDecoder(w.Body).Decode(&policies)
	if len(policies) != 0 {
		t.Errorf("expected empty list, got %d", len(policies))
	}
}

func TestLLMPolicies_CreateAndGet(t *testing.T) {
	env := setupAdminAPI(t)

	// Create.
	w := adminReq(t, env, http.MethodPost, "/admin/llm-policies",
		`{"name":"Test Policy","prompt":"Allow read-only ops","provider":"anthropic","model":"claude-sonnet-4-6"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(w.Body).Decode(&created)
	id, ok := created["id"].(string)
	if !ok || id == "" {
		t.Fatalf("expected id in response, got %v", created)
	}
	if created["name"] != "Test Policy" {
		t.Errorf("name: got %v", created["name"])
	}

	// List shows it.
	w = adminReq(t, env, http.MethodGet, "/admin/llm-policies", "")
	var policies []interface{}
	json.NewDecoder(w.Body).Decode(&policies)
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}

	// Get by ID.
	w = adminReq(t, env, http.MethodGet, "/admin/llm-policies/"+id, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var fetched map[string]interface{}
	json.NewDecoder(w.Body).Decode(&fetched)
	if fetched["id"] != id {
		t.Errorf("id mismatch: got %v", fetched["id"])
	}
}

func TestLLMPolicies_Fork(t *testing.T) {
	env := setupAdminAPI(t)

	// Create parent.
	w := adminReq(t, env, http.MethodPost, "/admin/llm-policies",
		`{"name":"Parent","prompt":"original prompt","provider":"","model":""}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var parent map[string]interface{}
	json.NewDecoder(w.Body).Decode(&parent)
	parentID := parent["id"].(string)

	// Fork it — creates a draft with the parent's content; editing happens in the draft editor.
	w = adminReq(t, env, http.MethodPost, "/admin/llm-policies/"+parentID+"/fork",
		`{"name":"Child"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("fork: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var child map[string]interface{}
	json.NewDecoder(w.Body).Decode(&child)
	if child["forked_from"] != parentID {
		t.Errorf("forked_from: want %q, got %v", parentID, child["forked_from"])
	}
	if child["name"] != "Child" {
		t.Errorf("name: got %v", child["name"])
	}
	if child["prompt"] != "original prompt" {
		t.Errorf("prompt: want parent's prompt, got %v", child["prompt"])
	}
	if child["status"] != "draft" {
		t.Errorf("status: want draft, got %v", child["status"])
	}
}

func TestLLMPolicies_GetNotFound(t *testing.T) {
	env := setupAdminAPI(t)
	w := adminReq(t, env, http.MethodGet, "/admin/llm-policies/llmpol_nonexistent", "")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestLLMPolicies_CreateMissingName(t *testing.T) {
	env := setupAdminAPI(t)
	w := adminReq(t, env, http.MethodPost, "/admin/llm-policies", `{"prompt":"no name"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
