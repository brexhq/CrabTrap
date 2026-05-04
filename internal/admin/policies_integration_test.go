package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/internal/llmpolicy"
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/internal/builder"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// newPoliciesAPI wires up a minimal admin API with only the policy store set —
// no eval runner needed for policy route tests.
func newPoliciesAPI(t *testing.T) (*API, *llmpolicy.PGStore) {
	t.Helper()
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken: {userID: "admin@example.com", role: "admin"},
		},
	}
	store := llmpolicy.NewPGStore(testPool)
	api := NewAPI(
		&stubAuditReader{},
		notifications.NewDispatcher(), notifications.NewSSEChannel("web"),
		validator, nil,
	)
	api.SetLLMPolicyStore(store)
	return api, store
}

// --- GET /admin/llm-policies ---

func TestPolicies_List_ReturnsCreatedPolicies(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	store.Create("policy-a", "prompt a", "", "", "", "", nil)
	store.Create("policy-b", "prompt b", "anthropic", "claude", "", "", nil)

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/llm-policies: got %d: %s", rr.Code, rr.Body.String())
	}
	var policies []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&policies)
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestPolicies_List_ExcludesDeleted(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	store.Create("keep", "prompt", "", "", "", "", nil)
	del, _ := store.Create("delete-me", "prompt", "", "", "", "", nil)
	store.Delete(del.ID)

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies", nil)
	var policies []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&policies)
	if len(policies) != 1 {
		t.Errorf("expected 1 policy after deletion, got %d", len(policies))
	}
	if policies[0]["name"] != "keep" {
		t.Errorf("expected surviving policy 'keep', got %q", policies[0]["name"])
	}
}

// --- POST /admin/llm-policies ---

func TestPolicies_Create_Returns201(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _ := newPoliciesAPI(t)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies", map[string]interface{}{
		"name": "new-policy", "prompt": "allow reads", "provider": "anthropic", "model": "claude",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/llm-policies: got %d: %s", rr.Code, rr.Body.String())
	}
	var p map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&p)
	if p["id"] == "" {
		t.Error("expected non-empty id in response")
	}
	if p["name"] != "new-policy" {
		t.Errorf("name = %q, want 'new-policy'", p["name"])
	}
}

func TestPolicies_Create_MissingName_Returns400(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _ := newPoliciesAPI(t)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies", map[string]interface{}{
		"prompt": "some prompt",
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rr.Code)
	}
}

// --- GET /admin/llm-policies/{id} ---

func TestPolicies_Get_Returns200(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	p, _ := store.Create("my-policy", "prompt text", "openai", "gpt-4", "", "", nil)

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/"+p.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/llm-policies/{id}: got %d: %s", rr.Code, rr.Body.String())
	}
	var got map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&got)
	if got["id"] != p.ID {
		t.Errorf("id = %q, want %q", got["id"], p.ID)
	}
	if got["prompt"] != "prompt text" {
		t.Errorf("prompt = %q, want 'prompt text'", got["prompt"])
	}
}

func TestPolicies_Get_NotFound_Returns404(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _ := newPoliciesAPI(t)

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/llmpol_doesnotexist", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// --- POST /admin/llm-policies/{id}/fork ---

func TestPolicies_Fork_Returns201(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	parent, _ := store.Create("parent", "original prompt", "anthropic", "claude", "", "", nil)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+parent.ID+"/fork", map[string]interface{}{
		"name": "child", "prompt": "updated prompt", "provider": "anthropic", "model": "claude",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /fork: got %d: %s", rr.Code, rr.Body.String())
	}
	var child map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&child)
	if child["forked_from"] != parent.ID {
		t.Errorf("forked_from = %q, want %q", child["forked_from"], parent.ID)
	}
	if child["id"] == parent.ID {
		t.Error("fork should have a new ID")
	}
}

func TestPolicies_Fork_NotFound_Returns404(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _ := newPoliciesAPI(t)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/llmpol_nope/fork",
		map[string]interface{}{"name": "child"})
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// --- DELETE /admin/llm-policies/{id} ---

func TestDeletePolicy_Returns204(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	p, _ := store.Create("delete-me", "prompt", "", "", "", "", nil)

	rr := doEvalRequest(t, api, http.MethodDelete, "/admin/llm-policies/"+p.ID, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE: got %d, want 204; body: %s", rr.Code, rr.Body.String())
	}

	// Must not appear in the list.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies", nil)
	var policies []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&policies)
	for _, pol := range policies {
		if pol["id"] == p.ID {
			t.Errorf("deleted policy %s still returned by GET /admin/llm-policies", p.ID)
		}
	}
}

func TestDeletePolicy_StillAccessibleByID(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	p, _ := store.Create("keep-accessible", "prompt", "", "", "", "", nil)
	doEvalRequest(t, api, http.MethodDelete, "/admin/llm-policies/"+p.ID, nil)

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/"+p.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET by ID after delete: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	var pol map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&pol)
	if pol["deleted_at"] == nil {
		t.Errorf("expected deleted_at to be set in GET response, got nil")
	}
}

func TestDeletePolicy_NotFound_Returns404(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _ := newPoliciesAPI(t)

	rr := doEvalRequest(t, api, http.MethodDelete, "/admin/llm-policies/llmpol_doesnotexist", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDeletePolicy_AssignedUsers_Returns409(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	p, _ := store.Create("in-use", "prompt", "", "", "", "", nil)
	_, err := testPool.Exec(context.Background(), `
		INSERT INTO users(id, is_admin, llm_policy_id) VALUES('user-policy-test', false, $1)
	`, p.ID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	rr := doEvalRequest(t, api, http.MethodDelete, "/admin/llm-policies/"+p.ID, nil)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- PUT /admin/llm-policies/{id} ---

func TestUpdateDraft_Returns200(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	draft, _ := store.Create("original", "old prompt", "", "", "", "draft", nil)

	rr := doEvalRequest(t, api, http.MethodPut, "/admin/llm-policies/"+draft.ID, map[string]interface{}{
		"name": "updated", "prompt": "new prompt", "provider": "", "model": "", "static_rules": []interface{}{},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT: got %d: %s", rr.Code, rr.Body.String())
	}
	var updated map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&updated)
	if updated["name"] != "updated" {
		t.Errorf("name = %v", updated["name"])
	}
	if updated["prompt"] != "new prompt" {
		t.Errorf("prompt = %v", updated["prompt"])
	}
}

func TestUpdateDraft_Published_Returns409(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	pub, _ := store.Create("pub", "prompt", "", "", "", "published", nil)

	rr := doEvalRequest(t, api, http.MethodPut, "/admin/llm-policies/"+pub.ID, map[string]interface{}{
		"name": "new", "prompt": "p", "provider": "", "model": "", "static_rules": []interface{}{},
	})
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 for published policy, got %d", rr.Code)
	}
}

// --- POST /admin/llm-policies/{id}/publish ---

func TestPublish_Returns200(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	draft, _ := store.Create("d", "prompt", "", "", "", "draft", nil)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+draft.ID+"/publish", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: got %d: %s", rr.Code, rr.Body.String())
	}
	var pol map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&pol)
	if pol["status"] != "published" {
		t.Errorf("status = %v, want published", pol["status"])
	}
}

func TestPublish_AlreadyPublished_Returns409(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	pub, _ := store.Create("p", "prompt", "", "", "", "published", nil)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+pub.ID+"/publish", nil)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

// --- POST /admin/llm-policies/{id}/agent ---

// stubTrafficReader satisfies builder.TrafficReader for testing without DB.
type stubPoliciesTrafficReader struct{}

func (r *stubPoliciesTrafficReader) AggregatePathGroups(_ string, _, _ time.Time) []builder.PathGroup {
	return nil
}
func (r *stubPoliciesTrafficReader) SampleRequestsForPath(_, _, _ string, _, _ time.Time, _ int) []builder.RequestSample {
	return nil
}

func TestAgent_UpdatesPolicy_StreamsResult(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{
				"policy_prompt":     "Allow read-only.",
				"static_rules": []types.StaticRule{{URLPattern: "https://api.example.com/", MatchType: "prefix"}},
			})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "update_policy", Input: input}},
			}, nil
		}
		return llm.Response{Text: "Policy applied.", StopReason: "end_turn"}, nil
	}}

	store := llmpolicy.NewPGStore(testPool)
	draft, _ := store.Create("d", "old prompt", "", "", "", "draft", nil)

	validator := &stubValidator{tokens: map[string]stubUser{adminToken: {userID: "admin@example.com", role: "admin"}}}
	api := NewAPI(&stubAuditReader{}, notifications.NewDispatcher(), notifications.NewSSEChannel("web"), validator, nil)
	api.SetLLMPolicyStore(store)
	agent := builder.NewPolicyAgent(&stubPoliciesTrafficReader{}, nil, thinking)
	api.SetAgent(agent)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+draft.ID+"/agent",
		map[string]interface{}{"message": "make it read-only", "history": []interface{}{}})
	if rr.Code != http.StatusOK {
		t.Fatalf("agent: got %d: %s", rr.Code, rr.Body.String())
	}

	// Parse SSE events from the response body.
	events := map[string]json.RawMessage{}
	scanner := bufio.NewScanner(strings.NewReader(rr.Body.String()))
	var curEvent string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			curEvent = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") && curEvent != "" {
			events[curEvent] = json.RawMessage(strings.TrimPrefix(line, "data: "))
			curEvent = ""
		}
	}

	if _, ok := events["result"]; !ok {
		t.Fatalf("no result event; got events: %v", events)
	}
	if _, ok := events["done"]; !ok {
		t.Error("no done event")
	}

	var result map[string]interface{}
	json.Unmarshal(events["result"], &result)
	if result["policy_prompt"] != "Allow read-only." {
		t.Errorf("policy_prompt = %v", result["policy_prompt"])
	}
	if result["policy_updated"] != true {
		t.Errorf("policy_updated = %v", result["policy_updated"])
	}

	// Verify the DB was updated.
	updated, _ := store.Get(draft.ID)
	if updated.Prompt != "Allow read-only." {
		t.Errorf("DB prompt = %q, want 'Allow read-only.'", updated.Prompt)
	}
}

func TestAgent_Published_Returns409(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	store := llmpolicy.NewPGStore(testPool)
	pub, _ := store.Create("p", "prompt", "", "", "", "published", nil)

	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: "ok", StopReason: "end_turn"}, nil
	}}
	validator := &stubValidator{tokens: map[string]stubUser{adminToken: {userID: "admin@example.com", role: "admin"}}}
	api := NewAPI(&stubAuditReader{}, notifications.NewDispatcher(), notifications.NewSSEChannel("web"), validator, nil)
	api.SetLLMPolicyStore(store)
	api.SetAgent(builder.NewPolicyAgent(&stubPoliciesTrafficReader{}, nil, thinking))

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+pub.ID+"/agent",
		map[string]interface{}{"message": "hello", "history": []interface{}{}})
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

func TestAgent_SavesChatHistory(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	// Agent returns a text response without calling any tools.
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: "I've reviewed the policy.", StopReason: "end_turn"}, nil
	}}

	store := llmpolicy.NewPGStore(testPool)
	draft, _ := store.Create("d", "p", "", "", "", "draft", nil)

	validator := &stubValidator{tokens: map[string]stubUser{adminToken: {userID: "admin@example.com", role: "admin"}}}
	api := NewAPI(&stubAuditReader{}, notifications.NewDispatcher(), notifications.NewSSEChannel("web"), validator, nil)
	api.SetLLMPolicyStore(store)
	api.SetAgent(builder.NewPolicyAgent(&stubPoliciesTrafficReader{}, nil, thinking))

	doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+draft.ID+"/agent",
		map[string]interface{}{"message": "review the policy", "history": []interface{}{}})

	savedMeta, _ := store.GetMetadata(draft.ID)
	if savedMeta == nil {
		t.Fatal("expected metadata to be set after agent run")
	}
	if len(savedMeta.ChatHistory) != 2 {
		t.Fatalf("expected 2 chat turns (user+assistant), got %d", len(savedMeta.ChatHistory))
	}
	if savedMeta.ChatHistory[0].Role != "user" || savedMeta.ChatHistory[0].Content != "review the policy" {
		t.Errorf("turn[0] = %+v", savedMeta.ChatHistory[0])
	}
	if savedMeta.ChatHistory[1].Role != "assistant" || savedMeta.ChatHistory[1].Content != "I've reviewed the policy." {
		t.Errorf("turn[1] = %+v", savedMeta.ChatHistory[1])
	}
}

func TestAgent_RemoveEndpoints_SavesSummariesWithoutPolicyUpdate(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	store := llmpolicy.NewPGStore(testPool)
	draft, _ := store.Create("d", "policy prompt", "", "", "", "draft", nil)
	// Pre-populate draft with endpoint summaries in metadata.
	store.UpsertMetadata(draft.ID, &types.PolicyMetadata{ //nolint:errcheck
		Source: "agent",
		EndpointSummaries: []types.PolicyEndpointSummary{
			{Method: "GET", PathPattern: "/v1/apps/{id}", Count: 100, Description: "Fetches an app."},
			{Method: "GET", PathPattern: "https://registry.npmjs.org/", Count: 50, Description: "NPM registry."},
		},
	})

	// Agent calls remove_endpoints only (no update_policy).
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{"patterns": []string{"npmjs.org"}})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "remove_endpoints", Input: input}},
			}, nil
		}
		return llm.Response{Text: "Removed NPM endpoints.", StopReason: "end_turn"}, nil
	}}

	validator := &stubValidator{tokens: map[string]stubUser{adminToken: {userID: "admin@example.com", role: "admin"}}}
	api := NewAPI(&stubAuditReader{}, notifications.NewDispatcher(), notifications.NewSSEChannel("web"), validator, nil)
	api.SetLLMPolicyStore(store)
	api.SetAgent(builder.NewPolicyAgent(&stubPoliciesTrafficReader{}, nil, thinking))

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+draft.ID+"/agent",
		map[string]interface{}{"message": "remove npm endpoints", "history": []interface{}{}})
	if rr.Code != http.StatusOK {
		t.Fatalf("agent: got %d: %s", rr.Code, rr.Body.String())
	}

	// Policy prompt must be unchanged (no update_policy was called).
	saved, _ := store.Get(draft.ID)
	if saved.Prompt != "policy prompt" {
		t.Errorf("prompt should be unchanged, got %q", saved.Prompt)
	}

	// Endpoint summaries must be updated (NPM entry removed).
	savedMeta, _ := store.GetMetadata(draft.ID)
	if savedMeta == nil {
		t.Fatal("expected metadata to be set")
	}
	if len(savedMeta.EndpointSummaries) != 1 {
		t.Errorf("expected 1 remaining summary, got %d", len(savedMeta.EndpointSummaries))
	}
	if savedMeta.EndpointSummaries[0].PathPattern != "/v1/apps/{id}" {
		t.Errorf("wrong summary remaining: %q", savedMeta.EndpointSummaries[0].PathPattern)
	}
}

func TestAgent_RemoveAllEndpoints_SavesEmptySummaries(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	store := llmpolicy.NewPGStore(testPool)
	draft, _ := store.Create("d", "p", "", "", "", "draft", nil)
	store.UpsertMetadata(draft.ID, &types.PolicyMetadata{ //nolint:errcheck
		Source:            "agent",
		EndpointSummaries: []types.PolicyEndpointSummary{{Method: "GET", PathPattern: "/v1/items", Count: 10, Description: "Lists items."}},
	})

	// Agent removes ALL endpoints — result.NewSummaries will be empty.
	callN := 0
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		if callN == 1 {
			input, _ := json.Marshal(map[string]interface{}{"patterns": []string{"/v1/items"}})
			return llm.Response{
				StopReason: "tool_use",
				ToolCalls:  []llm.ToolCall{{ID: "c1", Name: "remove_endpoints", Input: input}},
			}, nil
		}
		return llm.Response{Text: "All endpoints removed.", StopReason: "end_turn"}, nil
	}}

	validator := &stubValidator{tokens: map[string]stubUser{adminToken: {userID: "admin@example.com", role: "admin"}}}
	api := NewAPI(&stubAuditReader{}, notifications.NewDispatcher(), notifications.NewSSEChannel("web"), validator, nil)
	api.SetLLMPolicyStore(store)
	api.SetAgent(builder.NewPolicyAgent(&stubPoliciesTrafficReader{}, nil, thinking))

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+draft.ID+"/agent",
		map[string]interface{}{"message": "remove everything", "history": []interface{}{}})
	if rr.Code != http.StatusOK {
		t.Fatalf("agent: got %d: %s", rr.Code, rr.Body.String())
	}

	// Critical: empty summaries must be persisted so the next turn doesn't see stale data.
	savedMeta, _ := store.GetMetadata(draft.ID)
	if savedMeta == nil {
		t.Fatal("expected metadata to be set")
	}
	if len(savedMeta.EndpointSummaries) != 0 {
		t.Errorf("expected 0 summaries after removing all, got %d — stale summaries would confuse next agent turn",
			len(savedMeta.EndpointSummaries))
	}
	// Expect full turn: user msg, assistant w/ tool call, tool result, final assistant reply.
	if len(savedMeta.ChatHistory) != 4 {
		t.Errorf("expected 4 chat messages (user + tool call + tool result + reply), got %d", len(savedMeta.ChatHistory))
	}
	if savedMeta.ChatHistory[0].Role != "user" {
		t.Errorf("ChatHistory[0].Role = %q, want user", savedMeta.ChatHistory[0].Role)
	}
	if len(savedMeta.ChatHistory[1].ToolCalls) == 0 {
		t.Error("ChatHistory[1] should be assistant message with tool call")
	}
	if savedMeta.ChatHistory[2].ToolResult == nil {
		t.Error("ChatHistory[2] should be tool result")
	}
	if savedMeta.ChatHistory[3].Role != "assistant" || savedMeta.ChatHistory[3].Content == "" {
		t.Errorf("ChatHistory[3] should be final assistant reply, got %+v", savedMeta.ChatHistory[3])
	}
}

func TestUpdateDraft_MissingName_Returns400(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	draft, _ := store.Create("d", "p", "", "", "", "draft", nil)

	rr := doEvalRequest(t, api, http.MethodPut, "/admin/llm-policies/"+draft.ID, map[string]interface{}{
		"name": "", "prompt": "p", "provider": "", "model": "", "static_rules": []interface{}{},
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rr.Code)
	}
}

func TestUpdateDraft_StaticRulesPersisted(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	draft, _ := store.Create("d", "p", "", "", "", "draft", nil)

	rules := []types.StaticRule{
		{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix"},
		{Methods: []string{}, URLPattern: "https://cdn.example.com/", MatchType: "prefix"},
	}
	rr := doEvalRequest(t, api, http.MethodPut, "/admin/llm-policies/"+draft.ID, map[string]interface{}{
		"name": "d", "prompt": "p", "provider": "", "model": "", "static_rules": rules,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT: got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify rules are persisted to DB, not just returned.
	saved, err := store.Get(draft.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(saved.StaticRules) != 2 {
		t.Errorf("expected 2 rules in DB, got %d", len(saved.StaticRules))
	}
	if saved.StaticRules[0].URLPattern != "https://api.example.com/" {
		t.Errorf("rule[0].URLPattern = %q", saved.StaticRules[0].URLPattern)
	}
}

func TestUpdateDraft_DenyRulePersisted(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	draft, _ := store.Create("d", "p", "", "", "", "draft", nil)

	rules := []types.StaticRule{
		{Methods: []string{"DELETE"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "deny"},
	}
	rr := doEvalRequest(t, api, http.MethodPut, "/admin/llm-policies/"+draft.ID, map[string]interface{}{
		"name": "d", "prompt": "p", "provider": "", "model": "", "static_rules": rules,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT: got %d: %s", rr.Code, rr.Body.String())
	}

	saved, err := store.Get(draft.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(saved.StaticRules) != 1 {
		t.Fatalf("expected 1 rule in DB, got %d", len(saved.StaticRules))
	}
	if saved.StaticRules[0].Action != "deny" {
		t.Errorf("rule[0].Action = %q, want deny", saved.StaticRules[0].Action)
	}
}

func TestUpdateDraft_InvalidActionRejected(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	draft, _ := store.Create("d", "p", "", "", "", "draft", nil)

	rr := doEvalRequest(t, api, http.MethodPut, "/admin/llm-policies/"+draft.ID, map[string]interface{}{
		"name": "d", "prompt": "p", "provider": "", "model": "",
		"static_rules": []map[string]interface{}{
			{"url_pattern": "https://api.example.com/", "action": "maybe"},
		},
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid action, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPublish_NotFound_Returns404(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _ := newPoliciesAPI(t)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/llmpol_nonexistent/publish", nil)
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusConflict {
		// ErrPolicyNotDraft covers both "not found" and "already published" → 409 or 404.
		t.Errorf("expected 404 or 409, got %d", rr.Code)
	}
}

func TestPublish_ImmutableAfterPublish(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, store := newPoliciesAPI(t)

	draft, _ := store.Create("d", "original", "", "", "", "draft", nil)

	// Publish the draft.
	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+draft.ID+"/publish", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: %d: %s", rr.Code, rr.Body.String())
	}

	// Attempt to update the now-published policy — must be rejected.
	rr = doEvalRequest(t, api, http.MethodPut, "/admin/llm-policies/"+draft.ID, map[string]interface{}{
		"name": "d", "prompt": "modified", "provider": "", "model": "", "static_rules": []interface{}{},
	})
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 updating published policy, got %d", rr.Code)
	}

	// Verify the DB prompt is still the original.
	saved, _ := store.Get(draft.ID)
	if saved.Prompt != "original" {
		t.Errorf("prompt should be unchanged, got %q", saved.Prompt)
	}
}

// stubPoliciesTrafficReaderWithData returns fixed groups and samples for E2E tests.
type stubPoliciesTrafficReaderWithData struct{}

func (r *stubPoliciesTrafficReaderWithData) AggregatePathGroups(_ string, _, _ time.Time) []builder.PathGroup {
	return []builder.PathGroup{
		{Method: "GET", PathPattern: "/v1/applications/{id}", Count: 120},
		{Method: "POST", PathPattern: "/v1/jobs/{id}/move", Count: 15},
	}
}
func (r *stubPoliciesTrafficReaderWithData) SampleRequestsForPath(_, _, _ string, _, _ time.Time, _ int) []builder.RequestSample {
	return []builder.RequestSample{{URL: "https://api.greenhouse.io/v1/applications/123"}}
}

func TestAgent_AnalyzeAndUpdateE2E(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	// The thinking adapter calls analyze_traffic first, then update_policy.
	callN := 0
	fast := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: "Fetches or moves application records in Greenhouse."}, nil
	}}
	thinking := &llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		callN++
		switch callN {
		case 1:
			input, _ := json.Marshal(map[string]string{
				"user_id": "alice", "start_date": "2024-01-01T00:00:00Z", "end_date": "2024-03-31T00:00:00Z",
			})
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "analyze_traffic", Input: input}}}, nil
		case 2:
			input, _ := json.Marshal(map[string]interface{}{
				"policy_prompt":     "The agent may only access Greenhouse ATS read operations. Write operations require explicit approval.",
				"static_rules": []types.StaticRule{{Methods: []string{"GET"}, URLPattern: "https://api.greenhouse.io/", MatchType: "prefix"}},
			})
			return llm.Response{StopReason: "tool_use", ToolCalls: []llm.ToolCall{{ID: "c2", Name: "update_policy", Input: input}}}, nil
		default:
			return llm.Response{Text: "Policy created from Greenhouse traffic analysis.", StopReason: "end_turn"}, nil
		}
	}}

	store := llmpolicy.NewPGStore(testPool)
	draft, _ := store.Create("Greenhouse Policy", "", "", "", "", "draft", nil)

	validator := &stubValidator{tokens: map[string]stubUser{adminToken: {userID: "admin@example.com", role: "admin"}}}
	api := NewAPI(&stubAuditReader{}, notifications.NewDispatcher(), notifications.NewSSEChannel("web"), validator, nil)
	api.SetLLMPolicyStore(store)
	api.SetAgent(builder.NewPolicyAgent(&stubPoliciesTrafficReaderWithData{}, fast, thinking))

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/llm-policies/"+draft.ID+"/agent",
		map[string]interface{}{"message": "Build a policy for alice's Greenhouse traffic in Q1 2024", "history": []interface{}{}})
	if rr.Code != http.StatusOK {
		t.Fatalf("agent: got %d: %s", rr.Code, rr.Body.String())
	}

	// Collect all SSE events (multiple of same type possible).
	type sseEvent struct {
		typ  string
		data json.RawMessage
	}
	var allEvents []sseEvent
	scanner := bufio.NewScanner(strings.NewReader(rr.Body.String()))
	var curType string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			curType = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") && curType != "" {
			allEvents = append(allEvents, sseEvent{typ: curType, data: json.RawMessage(strings.TrimPrefix(line, "data: "))})
			curType = ""
		}
	}

	// Verify we got tool_start events for both tools.
	toolStarts := map[string]bool{}
	toolDones := map[string]bool{}
	for _, ev := range allEvents {
		var d map[string]interface{}
		json.Unmarshal(ev.data, &d)
		if ev.typ == "tool_start" {
			toolStarts[d["tool"].(string)] = true
		}
		if ev.typ == "tool_done" {
			toolDones[d["tool"].(string)] = true
		}
	}
	if !toolStarts["analyze_traffic"] {
		t.Error("expected tool_start event for analyze_traffic")
	}
	if !toolStarts["update_policy"] {
		t.Error("expected tool_start event for update_policy")
	}
	if !toolDones["analyze_traffic"] {
		t.Error("expected tool_done event for analyze_traffic")
	}
	if !toolDones["update_policy"] {
		t.Error("expected tool_done event for update_policy")
	}

	// Verify the final result event.
	var resultEvent map[string]interface{}
	for _, ev := range allEvents {
		if ev.typ == "result" {
			json.Unmarshal(ev.data, &resultEvent)
		}
	}
	if resultEvent == nil {
		t.Fatal("no result event in SSE stream")
	}
	if resultEvent["policy_updated"] != true {
		t.Errorf("policy_updated = %v", resultEvent["policy_updated"])
	}
	if !strings.Contains(resultEvent["policy_prompt"].(string), "Greenhouse") {
		t.Errorf("policy_prompt missing Greenhouse context: %q", resultEvent["policy_prompt"])
	}
	if resultEvent["message"] != "Policy created from Greenhouse traffic analysis." {
		t.Errorf("message = %q", resultEvent["message"])
	}

	// Verify DB: prompt updated and metadata has endpoint summaries.
	saved, err := store.Get(draft.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(saved.Prompt, "Greenhouse") {
		t.Errorf("DB prompt = %q", saved.Prompt)
	}
	if len(saved.StaticRules) != 1 {
		t.Errorf("expected 1 static rule in DB, got %d", len(saved.StaticRules))
	}
	savedMeta, _ := store.GetMetadata(draft.ID)
	if savedMeta == nil || len(savedMeta.EndpointSummaries) == 0 {
		t.Error("expected metadata with endpoint summaries saved to DB")
	}

	// Verify done event present.
	var hasDone bool
	for _, ev := range allEvents {
		if ev.typ == "done" {
			hasDone = true
		}
	}
	if !hasDone {
		t.Error("expected done event in SSE stream")
	}
}

// errors import is used in UpdateDraft test; ensure it's used.
var _ = errors.New
