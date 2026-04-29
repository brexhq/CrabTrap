package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/eval"
	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/internal/llmpolicy"
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

func truncateTables(t *testing.T) {
	t.Helper()
	testPool.Exec(context.Background(), "TRUNCATE llm_policies CASCADE")
	testPool.Exec(context.Background(), "TRUNCATE audit_log")
}

// newAuditAPI wires up an admin API with real PGAuditReader, PGUserStore,
// llmpolicy store, and eval store — all needed for audit + stats tests.
func newAuditAPI(t *testing.T) (*API, *PGAuditReader, *llmpolicy.PGStore, *PGUserStore) {
	t.Helper()
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken: {userID: "admin@example.com", isAdmin: true},
		},
	}
	reader := NewPGAuditReader(testPool)
	policyStore := llmpolicy.NewPGStore(testPool)
	userStore := NewPGUserStore(testPool)
	api := NewAPI(
		reader,
		notifications.NewDispatcher(), notifications.NewSSEChannel("web"),
		validator, userStore,
	)
	api.SetLLMPolicyStore(policyStore)
	api.SetEvalRunner(eval.NewPGStore(testPool), judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{Text: `{"decision":"ALLOW","reason":""}`}, nil
	}}))
	return api, reader, policyStore, userStore
}

// seedEntry is a convenience wrapper around reader.Add with sane defaults.
func seedEntry(reader *PGAuditReader, requestID, method, url, decision, policyID string, durationMs int64, approvedBy string) {
	reader.Add(types.AuditEntry{
		Timestamp:   time.Now(),
		RequestID:   requestID,
		Method:      method,
		URL:         url,
		Decision:    decision,
		Channel:     "llm",
		DurationMs:  durationMs,
		ApprovedBy:  approvedBy,
		LLMPolicyID: policyID,
		// LLMResponseID intentionally left blank; tests that need it create the row directly.
	})
}

// --- GET /admin/audit ---

// TestAudit_QueryFilter_PolicyID verifies that GET /admin/audit?policy_id= matches
// on the stored llm_policy_id column, not the user's current assignment.
func TestAudit_QueryFilter_PolicyID(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, policyStore, userStore := newAuditAPI(t)

	polA, _ := policyStore.Create("filter-pol-a", "prompt", "", "", "", "", nil)
	polB, _ := policyStore.Create("filter-pol-b", "prompt", "", "", "", "", nil)

	userStore.CreateUser(CreateUserRequest{ID: "filter-user"})
	userStore.UpdateUser("filter-user", UpdateUserRequest{LLMPolicyID: &polA.ID})

	seedEntry(reader, "fq1", "POST", "/x", "approved", polA.ID, 10, "llm")
	// Entry with no policy (non-LLM channel).
	reader.Add(types.AuditEntry{
		Timestamp: time.Now(), RequestID: "fq2",
		Method: "GET", URL: "/y", Decision: "approved", DurationMs: 5,
	})

	// Reassign user to B — must not affect fq1's attribution.
	userStore.UpdateUser("filter-user", UpdateUserRequest{LLMPolicyID: &polB.ID})

	time.Sleep(100 * time.Millisecond)

	// GET /admin/audit?policy_id=A should return exactly fq1.
	rr := doEvalRequest(t, api, http.MethodGet, "/admin/audit?policy_id="+polA.ID+"&limit=100", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit?policy_id=A: got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	entries := resp["entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("policy A filter: got %d entries, want 1", len(entries))
	}
	if len(entries) == 1 {
		if entries[0].(map[string]interface{})["request_id"] != "fq1" {
			t.Errorf("wrong entry returned")
		}
	}

	// GET /admin/audit?policy_id=B should return nothing (no entries made while on B).
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/audit?policy_id="+polB.ID+"&limit=100", nil)
	json.NewDecoder(rr.Body).Decode(&resp)
	entries = resp["entries"].([]interface{})
	if len(entries) != 0 {
		t.Errorf("policy B filter: got %d entries, want 0", len(entries))
	}
}

// TestAudit_LLMPolicyID_RoundTrip verifies llm_policy_id is persisted and
// returned in GET /admin/audit responses.
func TestAudit_LLMPolicyID_RoundTrip(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, policyStore, _ := newAuditAPI(t)

	pol, _ := policyStore.Create("roundtrip-pol", "prompt", "", "", "", "", nil)
	seedEntry(reader, "rt1", "POST", "/rt", "approved", pol.ID, 42, "llm")

	time.Sleep(100 * time.Millisecond)

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/audit?limit=10", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit: got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	entries := resp["entries"].([]interface{})
	if len(entries) == 0 {
		t.Fatal("no entries returned")
	}
	entry := entries[0].(map[string]interface{})
	if entry["llm_policy_id"] != pol.ID {
		t.Errorf("llm_policy_id = %q, want %q", entry["llm_policy_id"], pol.ID)
	}
}

func TestAuditList_OmitsPayloadsAndUsesLimitPlusOnePagination(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, _, _ := newAuditAPI(t)

	now := time.Now()
	reader.Add(types.AuditEntry{
		Timestamp:       now,
		RequestID:       "payload-list-1",
		Method:          "POST",
		URL:             "/payload",
		Operation:       "WRITE",
		Decision:        "approved",
		Channel:         "llm",
		ResponseStatus:  200,
		DurationMs:      25,
		RequestHeaders:  http.Header{"Content-Type": []string{"application/json"}},
		RequestBody:     `{"secret":"request"}`,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    `{"secret":"response"}`,
	})
	reader.Add(types.AuditEntry{
		Timestamp:       now.Add(time.Second),
		RequestID:       "payload-list-2",
		Method:          "POST",
		URL:             "/payload-2",
		Operation:       "WRITE",
		Decision:        "approved",
		Channel:         "llm",
		ResponseStatus:  200,
		DurationMs:      30,
		RequestHeaders:  http.Header{"Content-Type": []string{"application/json"}},
		RequestBody:     `{"secret":"request-2"}`,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
		ResponseBody:    `{"secret":"response-2"}`,
	})

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/audit?limit=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit: got %d: %s", rr.Code, rr.Body.String())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw list response: %v", err)
	}
	if _, ok := raw["total"]; ok {
		t.Fatal("list response includes total; want no exact count query")
	}
	var listResp struct {
		Entries []map[string]interface{} `json:"entries"`
		Offset  int                      `json:"offset"`
		Limit   int                      `json:"limit"`
		HasMore bool                     `json:"has_more"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if !listResp.HasMore {
		t.Fatalf("has_more = false, want true")
	}
	if listResp.Limit != 1 {
		t.Fatalf("limit = %d, want 1", listResp.Limit)
	}
	if len(listResp.Entries) != 1 {
		t.Fatalf("entries length = %d, want 1", len(listResp.Entries))
	}
	entry := listResp.Entries[0]
	for _, field := range []string{"request_headers", "request_body", "response_headers", "response_body"} {
		if _, ok := entry[field]; ok {
			t.Fatalf("list response includes %s; want payload fields omitted", field)
		}
	}

	id, _ := entry["id"].(string)
	if id == "" {
		t.Fatal("list response missing audit entry id")
	}
	requestID, _ := entry["request_id"].(string)
	wantRequestBody := `{"secret":"request-2"}`
	wantResponseBody := `{"secret":"response-2"}`
	if requestID == "payload-list-1" {
		wantRequestBody = `{"secret":"request"}`
		wantResponseBody = `{"secret":"response"}`
	}
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/audit/"+id, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit/{id}: got %d: %s", rr.Code, rr.Body.String())
	}
	var detail map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if detail["request_body"] != wantRequestBody {
		t.Fatalf("detail request_body = %v, want stored body", detail["request_body"])
	}
	if detail["response_body"] != wantResponseBody {
		t.Fatalf("detail response_body = %v, want stored body", detail["response_body"])
	}

	rr = doEvalRequest(t, api, http.MethodGet, "/admin/audit?limit=1&offset=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit page 2: got %d: %s", rr.Code, rr.Body.String())
	}
	if err := json.NewDecoder(rr.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode second list response: %v", err)
	}
	if listResp.HasMore {
		t.Fatalf("second page has_more = true, want false")
	}
	if len(listResp.Entries) != 1 {
		t.Fatalf("second page entries length = %d, want 1", len(listResp.Entries))
	}
}

// TestAudit_LLMResponseID_RoundTrip verifies that llm_response_id is stored and
// returned by GET /admin/audit/{id}, with reason populated from the JOIN.
func TestAudit_LLMResponseID_RoundTrip(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, policyStore, _ := newAuditAPI(t)

	pol, _ := policyStore.Create("llmresp-pol", "prompt", "", "", "", "", nil)

	// Create an llm_responses row directly via the eval store.
	evalStore := eval.NewPGStore(testPool)
	llmID, err := evalStore.CreateLLMResponse(types.LLMResponse{
		Model: "claude-test", DurationMs: 200, Result: "success",
		Decision: "ALLOW", Reason: "test reason",
	})
	if err != nil {
		t.Fatalf("CreateLLMResponse: %v", err)
	}

	reader.Add(types.AuditEntry{
		Timestamp: time.Now(), RequestID: "llmr1",
		Method: "GET", URL: "/api/x", Decision: "approved",
		Channel: "llm", DurationMs: 200, ApprovedBy: "llm",
		LLMPolicyID: pol.ID, LLMResponseID: llmID,
	})

	time.Sleep(100 * time.Millisecond)

	// GET /admin/audit?limit=1 should return the entry with llm_response_id set.
	rr := doEvalRequest(t, api, http.MethodGet, "/admin/audit?limit=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit: got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	entries := resp["entries"].([]interface{})
	if len(entries) == 0 {
		t.Fatal("no entries returned")
	}
	entry := entries[0].(map[string]interface{})
	if entry["llm_response_id"] != llmID {
		t.Errorf("llm_response_id = %v, want %q", entry["llm_response_id"], llmID)
	}
	// llm_reason should be populated via JOIN.
	if entry["llm_reason"] != "test reason" {
		t.Errorf("llm_reason = %v, want 'test reason'", entry["llm_reason"])
	}

	// GET /admin/llm-responses/{id} should return the row.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/llm-responses/"+llmID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/llm-responses: got %d: %s", rr.Code, rr.Body.String())
	}
	var lr map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&lr)
	if lr["model"] != "claude-test" {
		t.Errorf("model = %v, want claude-test", lr["model"])
	}
	if lr["result"] != "success" {
		t.Errorf("result = %v, want success", lr["result"])
	}
}

// --- GET /admin/llm-policies/{id}/stats ---

// TestAuditStats_UsesStoredPolicyID is the core regression test: stats must be
// computed from the stored llm_policy_id, not the user's current assignment.
func TestAuditStats_UsesStoredPolicyID(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, policyStore, userStore := newAuditAPI(t)

	polA, _ := policyStore.Create("stats-migration-a", "prompt", "", "", "", "", nil)
	polB, _ := policyStore.Create("stats-migration-b", "prompt", "", "", "", "", nil)

	userStore.CreateUser(CreateUserRequest{ID: "migrating-user"})
	userStore.UpdateUser("migrating-user", UpdateUserRequest{LLMPolicyID: &polA.ID})

	seedEntry(reader, "m1", "POST", "/a", "approved", polA.ID, 100, "llm")
	seedEntry(reader, "m2", "POST", "/a", "denied", polA.ID, 80, "llm")

	// Reassign to B; one new entry.
	userStore.UpdateUser("migrating-user", UpdateUserRequest{LLMPolicyID: &polB.ID})
	seedEntry(reader, "m3", "GET", "/b", "approved", polB.ID, 50, "llm")

	time.Sleep(100 * time.Millisecond)

	// Policy A stats should show total=2.
	rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/"+polA.ID+"/stats", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET stats A: got %d: %s", rr.Code, rr.Body.String())
	}
	var statsA map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&statsA)
	if total := int(statsA["total"].(float64)); total != 2 {
		t.Errorf("policy A total: got %d, want 2", total)
	}

	// Policy B stats should show total=1.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/"+polB.ID+"/stats", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET stats B: got %d: %s", rr.Code, rr.Body.String())
	}
	var statsB map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&statsB)
	if total := int(statsB["total"].(float64)); total != 1 {
		t.Errorf("policy B total: got %d, want 1", total)
	}
}

// TestAuditStats_Counts verifies decision counts, durations, percentiles,
// per-approver breakdown, and time-series buckets via GET /admin/llm-policies/{id}/stats.
func TestAuditStats_Counts(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, policyStore, userStore := newAuditAPI(t)

	polA, _ := policyStore.Create("policy-a", "prompt a", "openai", "gpt-4", "", "", nil)
	polB, _ := policyStore.Create("policy-b", "prompt b", "anthropic", "claude", "", "", nil)

	userStore.CreateUser(CreateUserRequest{ID: "stats-user-a1"})
	userStore.CreateUser(CreateUserRequest{ID: "stats-user-a2"})
	userStore.CreateUser(CreateUserRequest{ID: "stats-user-b1"})
	userStore.UpdateUser("stats-user-a1", UpdateUserRequest{LLMPolicyID: &polA.ID})
	userStore.UpdateUser("stats-user-a2", UpdateUserRequest{LLMPolicyID: &polA.ID})
	userStore.UpdateUser("stats-user-b1", UpdateUserRequest{LLMPolicyID: &polB.ID})

	now := time.Now()
	for _, e := range []types.AuditEntry{
		{UserID: "stats-user-a1", Timestamp: now, RequestID: "r1", Method: "POST", URL: "/api/foo", Decision: "approved", ApprovedBy: "llm", Channel: "llm", DurationMs: 100, LLMPolicyID: polA.ID},
		{UserID: "stats-user-a1", Timestamp: now, RequestID: "r2", Method: "POST", URL: "/api/foo", Decision: "approved", ApprovedBy: "llm", Channel: "llm", DurationMs: 200, LLMPolicyID: polA.ID},
		{UserID: "stats-user-a1", Timestamp: now, RequestID: "r3", Method: "POST", URL: "/api/bar", Decision: "denied", ApprovedBy: "llm", Channel: "llm", DurationMs: 50, LLMPolicyID: polA.ID},
		{UserID: "stats-user-a2", Timestamp: now, RequestID: "r4", Method: "GET", URL: "/api/baz", Decision: "approved", ApprovedBy: "web-admin", Channel: "web", DurationMs: 300, LLMPolicyID: polA.ID},
		{UserID: "stats-user-b1", Timestamp: now, RequestID: "r5", Method: "GET", URL: "/api/x", Decision: "approved", ApprovedBy: "llm", Channel: "llm", DurationMs: 999, LLMPolicyID: polB.ID},
	} {
		reader.Add(e)
	}

	time.Sleep(200 * time.Millisecond)

	t.Run("policy_a", func(t *testing.T) {
		rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/"+polA.ID+"/stats", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET stats: got %d: %s", rr.Code, rr.Body.String())
		}
		var stats map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&stats)

		if total := int(stats["total"].(float64)); total != 4 {
			t.Errorf("total: got %d, want 4", total)
		}
		// overall avg: (100+200+50+300)/4 = 162
		if avg := int(stats["avg_duration_ms"].(float64)); avg != 162 {
			t.Errorf("avg_duration_ms: got %d, want 162", avg)
		}
		// p50 <= p95 <= p99, all non-zero
		p50 := int(stats["p50_duration_ms"].(float64))
		p95 := int(stats["p95_duration_ms"].(float64))
		p99 := int(stats["p99_duration_ms"].(float64))
		if p50 == 0 || p95 == 0 || p99 == 0 {
			t.Errorf("percentiles should be non-zero: p50=%d p95=%d p99=%d", p50, p95, p99)
		}
		if p50 > p95 || p95 > p99 {
			t.Errorf("percentile ordering violated: p50=%d p95=%d p99=%d", p50, p95, p99)
		}

		byDecision := stats["by_decision"].(map[string]interface{})

		approved := byDecision["approved"].(map[string]interface{})
		if count := int(approved["count"].(float64)); count != 3 {
			t.Errorf("approved count: got %d, want 3", count)
		}
		// avg for approved: (100+200+300)/3 = 200
		if avg := int(approved["avg_duration_ms"].(float64)); avg != 200 {
			t.Errorf("approved avg_duration_ms: got %d, want 200", avg)
		}
		byApprover := approved["by_approver"].([]interface{})
		if len(byApprover) != 2 {
			t.Errorf("approved approver count: got %d, want 2 (llm + web-admin)", len(byApprover))
		}

		denied := byDecision["denied"].(map[string]interface{})
		if count := int(denied["count"].(float64)); count != 1 {
			t.Errorf("denied count: got %d, want 1", count)
		}
		if avg := int(denied["avg_duration_ms"].(float64)); avg != 50 {
			t.Errorf("denied avg_duration_ms: got %d, want 50", avg)
		}
		// Single denied entry → p50 = 50
		if p50 := int(denied["p50_duration_ms"].(float64)); p50 != 50 {
			t.Errorf("denied p50: got %d, want 50", p50)
		}

		// All entries are today → 1 time-series bucket.
		ts := stats["time_series"].([]interface{})
		if len(ts) != 1 {
			t.Errorf("time_series buckets: got %d, want 1", len(ts))
		} else {
			bucket := ts[0].(map[string]interface{})
			if total := int(bucket["total"].(float64)); total != 4 {
				t.Errorf("time_series total: got %d, want 4", total)
			}
			if approved := int(bucket["approved"].(float64)); approved != 3 {
				t.Errorf("time_series approved: got %d, want 3", approved)
			}
			if denied := int(bucket["denied"].(float64)); denied != 1 {
				t.Errorf("time_series denied: got %d, want 1", denied)
			}
		}
	})

	t.Run("policy_b", func(t *testing.T) {
		rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/"+polB.ID+"/stats", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET stats: got %d: %s", rr.Code, rr.Body.String())
		}
		var stats map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&stats)
		if total := int(stats["total"].(float64)); total != 1 {
			t.Errorf("total: got %d, want 1", total)
		}
		// Single entry at 999ms → p50 = 999
		if p50 := int(stats["p50_duration_ms"].(float64)); p50 != 999 {
			t.Errorf("p50: got %d, want 999", p50)
		}
	})

	t.Run("nonexistent_policy", func(t *testing.T) {
		rr := doEvalRequest(t, api, http.MethodGet, "/admin/llm-policies/llmpol_doesnotexist/stats", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET stats: got %d: %s", rr.Code, rr.Body.String())
		}
		var stats map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&stats)
		if total := int(stats["total"].(float64)); total != 0 {
			t.Errorf("total: got %d, want 0", total)
		}
		if stats["time_series"] != nil {
			ts := stats["time_series"].([]interface{})
			if len(ts) != 0 {
				t.Errorf("time_series: got %d buckets, want 0", len(ts))
			}
		}
	})
}
