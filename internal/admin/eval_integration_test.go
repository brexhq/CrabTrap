package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/eval"
	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llm"
	"github.com/brexhq/CrabTrap/internal/llmpolicy"
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

func newAllowJudge() *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{
			Text:         `{"decision":"ALLOW","reason":"looks fine"}`,
			DurationMs:   100,
			InputTokens:  50,
			OutputTokens: 10,
		}, nil
	}})
}

func newDenyJudge() *judge.LLMJudge {
	return judge.NewLLMJudge(&llm.TestAdapter{Fn: func(req llm.Request) (llm.Response, error) {
		return llm.Response{
			Text:         `{"decision":"DENY","reason":"blocked"}`,
			DurationMs:   80,
			InputTokens:  50,
			OutputTokens: 8,
		}, nil
	}})
}

// seedAuditEntry inserts a minimal audit_log row for use in eval tests.
func seedAuditEntry(t *testing.T, method, url, decision, policyID string) string {
	t.Helper()
	reader := NewPGAuditReader(testPool)
	entry := types.AuditEntry{
		Timestamp:   time.Now(),
		RequestID:   "req_" + method + "_" + decision,
		Method:      method,
		URL:         url,
		Operation:   "READ",
		Decision:    decision,
		LLMPolicyID: policyID,
	}
	reader.Add(entry)
	// Fetch back to get the DB-assigned id.
	entries := reader.Query(AuditFilter{Method: method, Limit: 1})
	if len(entries) == 0 {
		t.Fatalf("seedAuditEntry: failed to retrieve seeded entry (method=%s url=%s)", method, url)
	}
	return entries[0].ID
}

// newEvalAPI wires up a full admin API with real PG-backed stores and a judge.
func newEvalAPI(t *testing.T, j *judge.LLMJudge) (*API, *llmpolicy.PGStore) {
	t.Helper()
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken: {userID: "admin@example.com", role: "admin"},
		},
	}
	policyStore := llmpolicy.NewPGStore(testPool)
	evalStore := eval.NewPGStore(testPool)
	reader := NewPGAuditReader(testPool)

	api := NewAPI(
		reader,
		notifications.NewDispatcher(),
		notifications.NewSSEChannel("web"),
		validator,
		nil,
	)
	api.SetLLMPolicyStore(policyStore)
	api.SetEvalRunner(evalStore, j)
	return api, policyStore
}

// doEvalRequest is a thin helper for making eval API requests with the admin token.
func doEvalRequest(t *testing.T, api *API, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("doEvalRequest: encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	mux.ServeHTTP(rr, req)
	return rr
}

// pollRunUntilDone polls GET /admin/evals/{id} until status is neither "pending"
// nor "running", or until the timeout expires.
func pollRunUntilDone(t *testing.T, api *API, runID string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rr := doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET /admin/evals/%s: status %d: %s", runID, rr.Code, rr.Body.String())
		}
		var run map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&run); err != nil {
			t.Fatalf("decode run: %v", err)
		}
		status, _ := run["status"].(string)
		if status != "pending" && status != "running" {
			return run
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pollRunUntilDone: timed out after %s waiting for run %s to finish", timeout, runID)
	return nil
}

// TestEvalFlow_CreateRun_Completes is the main end-to-end test:
// POST /admin/evals → run completes → GET /admin/evals/{id} shows stats →
// GET /admin/evals/{id}/results shows per-entry replay decisions.
func TestEvalFlow_CreateRun_Completes(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())

	policy, err := policyStore.Create("eval-test-policy", "allow everything", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	// Seed two audit entries (one "approved", one "denied" originally).
	seedAuditEntry(t, "GET", "/api/read", "approved", policy.ID)
	seedAuditEntry(t, "POST", "/api/write", "denied", policy.ID)

	// Create the eval run via the HTTP API.
	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 10},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: status %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatalf("decode created run: %v", err)
	}
	runID, _ := created["id"].(string)
	if runID == "" {
		t.Fatalf("expected run id in response, got: %v", created)
	}
	if created["status"] != "pending" {
		t.Errorf("initial status = %q, want pending", created["status"])
	}

	// Poll until completed.
	run := pollRunUntilDone(t, api, runID, 5*time.Second)

	if run["status"] != "completed" {
		t.Errorf("final status = %q, want completed; error = %v", run["status"], run["error"])
	}
	// Both entries replayed as ALLOW; original decisions were "approved" and "denied".
	// agreed: GET replays ALLOW matches "approved"→ALLOW = 1
	// disagreed: POST replays ALLOW but "denied"→DENY = 1
	if total := int(run["total"].(float64)); total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if agreed := int(run["agreed"].(float64)); agreed != 1 {
		t.Errorf("agreed = %d, want 1", agreed)
	}
	if disagreed := int(run["disagreed"].(float64)); disagreed != 1 {
		t.Errorf("disagreed = %d, want 1", disagreed)
	}
	if errored := int(run["errored"].(float64)); errored != 0 {
		t.Errorf("errored = %d, want 0", errored)
	}

	// Verify results via GET /admin/evals/{id}/results.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET results: status %d: %s", rr.Code, rr.Body.String())
	}
	var resultsResp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resultsResp); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	results, _ := resultsResp["results"].([]interface{})
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if total, _ := resultsResp["total"].(float64); int(total) != 2 {
		t.Errorf("total = %v, want 2", resultsResp["total"])
	}
	for _, ri := range results {
		r, _ := ri.(map[string]interface{})
		if r["replay_decision"] != "ALLOW" {
			t.Errorf("entry %s: replay_decision = %q, want ALLOW", r["entry_id"], r["replay_decision"])
		}
		if lbl, _ := r["label_decision"].(string); lbl != "" {
			t.Errorf("entry %s: label_decision = %q, want empty (no labels yet)", r["entry_id"], lbl)
		}
		// llm_response_id must be set since the spy returns model metadata.
		if id, _ := r["llm_response_id"].(string); id == "" {
			t.Errorf("entry %s: llm_response_id should be set", r["entry_id"])
		}
		// replay_reason populated from llm_responses JOIN.
		if reason, _ := r["replay_reason"].(string); reason == "" {
			t.Errorf("entry %s: replay_reason should be populated from llm_responses", r["entry_id"])
		}
	}
}

// TestEvalFlow_LabelUpdatesAgreed checks that adding a label via the admin API
// is reflected in subsequent GET /admin/evals/{id} stats.
func TestEvalFlow_LabelUpdatesAgreed(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	// Judge always returns DENY.
	api, policyStore := newEvalAPI(t, newDenyJudge())

	policy, _ := policyStore.Create("label-test-policy", "deny all", "", "", "", "", nil)

	// Entry originally "approved"; judge replays as DENY → disagrees without label.
	entryID := seedAuditEntry(t, "GET", "/api/sensitive", "approved", policy.ID)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 10},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: status %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)

	run := pollRunUntilDone(t, api, runID, 5*time.Second)
	if run["status"] != "completed" {
		t.Fatalf("run did not complete: %v", run)
	}

	// Without label: disagreed=1 (DENY vs approved→ALLOW), labeled=0.
	if int(run["disagreed"].(float64)) != 1 || int(run["labeled"].(float64)) != 0 {
		t.Errorf("before label: disagreed=%v labeled=%v, want 1,0", run["disagreed"], run["labeled"])
	}

	// Add label: DENY was correct for this entry.
	rr = doEvalRequest(t, api, http.MethodPut, "/admin/audit/"+entryID+"/label",
		map[string]string{"decision": "DENY", "note": "this should have been blocked"})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT label: status %d: %s", rr.Code, rr.Body.String())
	}

	// Re-fetch run: agreed should now be 1, disagreed 0, labeled 1.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID, nil)
	json.NewDecoder(rr.Body).Decode(&run)
	if int(run["agreed"].(float64)) != 1 || int(run["disagreed"].(float64)) != 0 || int(run["labeled"].(float64)) != 1 {
		t.Errorf("after label: agreed=%v disagreed=%v labeled=%v, want 1,0,1",
			run["agreed"], run["disagreed"], run["labeled"])
	}

	// Verify label shows up in results.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results", nil)
	var resultsResp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resultsResp)
	results, _ := resultsResp["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r0, _ := results[0].(map[string]interface{})
	if r0["label_decision"] != "DENY" {
		t.Errorf("results[0].label_decision = %v, want DENY", r0["label_decision"])
	}
}

// TestEvalFlow_NoJudge_Returns503 ensures POST /admin/evals returns 503 when the
// eval runner is not configured (simulates deployment without LLM judge).
func TestEvalFlow_NoJudge_Returns503(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	// API with evalStore but no judge (SetEvalRunner not called).
	validator := &stubValidator{tokens: map[string]stubUser{
		adminToken: {userID: "admin@example.com", role: "admin"},
	}}
	policyStore := llmpolicy.NewPGStore(testPool)
	evalStore := eval.NewPGStore(testPool)

	api := NewAPI(&stubAuditReader{},
		notifications.NewDispatcher(), notifications.NewSSEChannel("web"),
		validator, nil)
	api.SetLLMPolicyStore(policyStore)
	api.evalStore = evalStore // store set, but evalJudge remains nil

	policy, _ := policyStore.Create("no-judge-policy", "prompt", "", "", "", "", nil)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
	})
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 with no judge, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestEvalFlow_UnknownPolicy_Returns404 ensures POST /admin/evals returns 404
// when the policy_id does not exist.
func TestEvalFlow_UnknownPolicy_Returns404(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, _ := newEvalAPI(t, newAllowJudge())

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": "llmpol_doesnotexist",
	})
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown policy, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestEvalList_ReturnsRunsForPolicy verifies GET /admin/evals?policy_id= filters
// runs to only those belonging to the given policy.
func TestEvalList_ReturnsRunsForPolicy(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())

	polA, _ := policyStore.Create("policy-a", "prompt", "", "", "", "", nil)
	polB, _ := policyStore.Create("policy-b", "prompt", "", "", "", "", nil)

	// Create one run for each policy.
	doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{"policy_id": polA.ID})
	doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{"policy_id": polA.ID})
	doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{"policy_id": polB.ID})

	// Unfiltered list should return all three.
	rr := doEvalRequest(t, api, http.MethodGet, "/admin/evals", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/evals: got %d: %s", rr.Code, rr.Body.String())
	}
	var all []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&all)
	if len(all) != 3 {
		t.Errorf("unfiltered: expected 3 runs, got %d", len(all))
	}

	// Filtered by polA should return only two.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals?policy_id="+polA.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/evals?policy_id: got %d: %s", rr.Code, rr.Body.String())
	}
	var filtered []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&filtered)
	if len(filtered) != 2 {
		t.Errorf("filtered by polA: expected 2 runs, got %d", len(filtered))
	}
	for _, r := range filtered {
		if r["policy_id"] != polA.ID {
			t.Errorf("run policy_id = %q, want %q", r["policy_id"], polA.ID)
		}
	}
}

// TestEvalFlow_StaticRuleReplayedWithoutLLM is an end-to-end test that verifies
// an audit entry originally decided by a static rule is replayed via the new
// policy's static rules — without calling the LLM judge.
//
// Setup:
//   - Judge always DENYs (so if the LLM is reached, we'll see DENY).
//   - Policy has a static allow rule matching GET https://api.example.com/*.
//   - Two audit entries: one GET (matches static allow) and one POST (no match → LLM).
//
// Expected:
//   - GET result: ALLOW, approved_by=llm-static-rule (static rule, no LLM call).
//   - POST result: DENY, approved_by=llm (fell through to judge).
func TestEvalFlow_StaticRuleReplayedWithoutLLM(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newDenyJudge())

	staticRules := []types.StaticRule{
		{Methods: []string{"GET"}, URLPattern: "https://api.example.com/", MatchType: "prefix", Action: "allow"},
	}
	policy, err := policyStore.Create("static-rule-replay-policy", "deny everything", "", "", "", "", staticRules)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	reader := NewPGAuditReader(testPool)

	// Entry originally decided by a static rule — must be replayed.
	reader.Add(types.AuditEntry{
		Timestamp: time.Now(), RequestID: "req-static", Method: "GET",
		URL: "https://api.example.com/v1/items", Operation: "READ",
		Decision: "approved", Channel: "llm", ApprovedBy: "llm-static-rule",
		LLMPolicyID: policy.ID,
	})
	// Entry originally decided by LLM — must also be replayed.
	reader.Add(types.AuditEntry{
		Timestamp: time.Now(), RequestID: "req-llm", Method: "POST",
		URL: "https://api.example.com/v1/items", Operation: "WRITE",
		Decision: "approved", Channel: "llm", ApprovedBy: "llm",
		LLMPolicyID: policy.ID,
	})

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 10},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: status %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	run := pollRunUntilDone(t, api, created["id"].(string), 5*time.Second)

	if run["status"] != "completed" {
		t.Fatalf("run did not complete: %v", run)
	}
	if total := int(run["total"].(float64)); total != 2 {
		t.Errorf("total = %d, want 2", total)
	}

	// Fetch results and verify per-entry decisions.
	runID := created["id"].(string)
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET results: status %d: %s", rr.Code, rr.Body.String())
	}
	results, _ := decodeResultsResp(t, rr)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	byMethod := map[string]map[string]interface{}{}
	for _, r := range results {
		byMethod[r["method"].(string)] = r
	}

	// GET should be handled by the static allow rule — no LLM call.
	get := byMethod["GET"]
	if get == nil {
		t.Fatal("no result for GET entry")
	}
	if get["replay_decision"] != "ALLOW" {
		t.Errorf("GET replay_decision = %q, want ALLOW", get["replay_decision"])
	}
	if get["approved_by"] != "llm-static-rule" {
		t.Errorf("GET approved_by = %q, want llm-static-rule", get["approved_by"])
	}
	if id, _ := get["llm_response_id"].(string); id != "" {
		t.Errorf("GET llm_response_id = %q, want empty (static rule should not produce LLM response)", id)
	}

	// POST should fall through to the LLM judge (which always DENYs).
	post := byMethod["POST"]
	if post == nil {
		t.Fatal("no result for POST entry")
	}
	if post["replay_decision"] != "DENY" {
		t.Errorf("POST replay_decision = %q, want DENY", post["replay_decision"])
	}
	if post["approved_by"] != "llm" {
		t.Errorf("POST approved_by = %q, want llm", post["approved_by"])
	}
	if id, _ := post["llm_response_id"].(string); id == "" {
		t.Error("POST llm_response_id should be set (LLM judge was called)")
	}
}

// TestEvalList_Empty verifies GET /admin/evals returns an empty array (not null)
// when no runs exist.
func TestEvalList_Empty(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, _ := newEvalAPI(t, newAllowJudge())

	rr := doEvalRequest(t, api, http.MethodGet, "/admin/evals", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/evals: got %d: %s", rr.Code, rr.Body.String())
	}
	var runs []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&runs)
	if len(runs) != 0 {
		t.Errorf("expected empty list, got %d runs", len(runs))
	}
}

// TestEvalFlow_DeleteLabel_RemovesLabelFromResults verifies DELETE /admin/audit/{id}/label
// clears the label and is reflected in GET /admin/evals/{id}/results.
func TestEvalFlow_DeleteLabel_RemovesLabelFromResults(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newDenyJudge())

	policy, _ := policyStore.Create("delete-label-policy", "deny all", "", "", "", "", nil)
	entryID := seedAuditEntry(t, "GET", "/api/x", "approved", policy.ID)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 10},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: got %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)
	pollRunUntilDone(t, api, runID, 5*time.Second)

	// Add a label.
	rr = doEvalRequest(t, api, http.MethodPut, "/admin/audit/"+entryID+"/label",
		map[string]string{"decision": "DENY", "note": "confirmed"})
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT label: got %d: %s", rr.Code, rr.Body.String())
	}

	// Delete the label.
	rr = doEvalRequest(t, api, http.MethodDelete, "/admin/audit/"+entryID+"/label", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE label: got %d: %s", rr.Code, rr.Body.String())
	}

	// Label should be gone from results.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results", nil)
	var resultsResp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resultsResp)
	results, _ := resultsResp["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r0, _ := results[0].(map[string]interface{})
	if lbl, _ := r0["label_decision"].(string); lbl != "" {
		t.Errorf("label_decision = %q after delete, want empty", lbl)
	}
}

// decodeResultsResp decodes a { results: [...], total: N } API response.
func decodeResultsResp(t *testing.T, rr *httptest.ResponseRecorder) ([]map[string]interface{}, int) {
	t.Helper()
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode results response: %v", err)
	}
	raw, _ := resp["results"].([]interface{})
	total := int(resp["total"].(float64))
	out := make([]map[string]interface{}, len(raw))
	for i, r := range raw {
		out[i], _ = r.(map[string]interface{})
	}
	return out, total
}

// TestEvalResults_FilterByApprovedBy verifies that approved_by query param
// filters results correctly.
func TestEvalResults_FilterByApprovedBy(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())
	policy, _ := policyStore.Create("filter-approver-policy", "allow all", "", "", "", "", nil)

	// One entry that will hit the judge, one that matches passthrough rule
	seedAuditEntry(t, "GET", "/api/read", "approved", policy.ID)
	seedAuditEntry(t, "POST", "/api/write", "approved", policy.ID)

	reader := NewPGAuditReader(testPool)
	reader.Add(types.AuditEntry{
		Timestamp: time.Now(), RequestID: "req-llm", Method: "DELETE", URL: "/api/x",
		Operation: "WRITE", Decision: "approved", Channel: "llm", ApprovedBy: "llm",
		LLMPolicyID: policy.ID,
	})

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 50},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: status %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)
	pollRunUntilDone(t, api, runID, 5*time.Second)

	// All results should have approved_by=llm (judge always ALLOWs)
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results?approved_by=llm", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET results?approved_by=llm: status %d", rr.Code)
	}
	res, total := decodeResultsResp(t, rr)
	if total == 0 || len(res) == 0 {
		t.Errorf("expected results with approved_by=llm, got total=%d len=%d", total, len(res))
	}
	for _, r := range res {
		if r["approved_by"] != "llm" {
			t.Errorf("approved_by = %q, want llm", r["approved_by"])
		}
	}

	// No results should have approved_by=llm-passthrough
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results?approved_by=llm-passthrough", nil)
	res, total = decodeResultsResp(t, rr)
	if total != 0 || len(res) != 0 {
		t.Errorf("expected 0 results for approved_by=llm-passthrough, got total=%d", total)
	}
}

// TestEvalResults_FilterByMatched verifies matched=false returns only disagreed results.
func TestEvalResults_FilterByMatched(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	// Judge always DENYs — entries originally "approved" will disagree.
	api, policyStore := newEvalAPI(t, newDenyJudge())
	policy, _ := policyStore.Create("filter-matched-policy", "deny all", "", "", "", "", nil)

	seedAuditEntry(t, "GET", "/api/1", "approved", policy.ID) // DENY vs approved → disagree
	seedAuditEntry(t, "GET", "/api/2", "denied", policy.ID)   // DENY vs denied  → agree

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 10},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)
	pollRunUntilDone(t, api, runID, 5*time.Second)

	// matched=false → only disagreed (1 result)
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results?matched=false", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET results?matched=false: %d: %s", rr.Code, rr.Body.String())
	}
	res, total := decodeResultsResp(t, rr)
	if total != 1 || len(res) != 1 {
		t.Errorf("matched=false: got total=%d len=%d, want 1", total, len(res))
	}

	// matched=true → only agreed (1 result)
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results?matched=true", nil)
	res, total = decodeResultsResp(t, rr)
	if total != 1 || len(res) != 1 {
		t.Errorf("matched=true: got total=%d len=%d, want 1", total, len(res))
	}
}

// TestEvalResults_ResponseIncludesTotal verifies the response shape is
// { results: [...], total: N } and total reflects the filter.
func TestEvalResults_ResponseIncludesTotal(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())
	policy, _ := policyStore.Create("response-shape-policy", "allow all", "", "", "", "", nil)

	seedAuditEntry(t, "GET", "/api/1", "approved", policy.ID)
	seedAuditEntry(t, "POST", "/api/2", "denied", policy.ID)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 10},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)
	pollRunUntilDone(t, api, runID, 5*time.Second)

	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID+"/results", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET results: %d: %s", rr.Code, rr.Body.String())
	}
	res, total := decodeResultsResp(t, rr)
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(res) != 2 {
		t.Errorf("len(results) = %d, want 2", len(res))
	}
}

// TestEvalRun_PolicyNameReturnedInListAndGet verifies that policy_name is populated
// on both GET /admin/evals (list) and GET /admin/evals/{id} responses.
func TestEvalRun_PolicyNameReturnedInListAndGet(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())
	policy, _ := policyStore.Create("my-named-policy", "allow all", "", "", "", "", nil)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)
	pollRunUntilDone(t, api, runID, 5*time.Second)

	// GET /admin/evals/{id}
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/evals/%s: %d: %s", runID, rr.Code, rr.Body.String())
	}
	var run map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&run)
	if run["policy_name"] != "my-named-policy" {
		t.Errorf("GET run: policy_name = %q, want my-named-policy", run["policy_name"])
	}

	// GET /admin/evals (list)
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var runs []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&runs)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run in list, got %d", len(runs))
	}
	if runs[0]["policy_name"] != "my-named-policy" {
		t.Errorf("list run: policy_name = %q, want my-named-policy", runs[0]["policy_name"])
	}
}

// TestEvalRun_PolicyNameReturnedAfterDelete verifies that policy_name is still
// returned on eval runs after the policy has been soft-deleted.
func TestEvalRun_PolicyNameReturnedAfterDelete(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())
	policy, _ := policyStore.Create("policy-to-delete", "allow all", "", "", "", "", nil)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)
	pollRunUntilDone(t, api, runID, 5*time.Second)

	// Soft-delete the policy.
	if err := policyStore.Delete(policy.ID); err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	// GET /admin/evals/{id} — name must still be present.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/evals/%s: %d: %s", runID, rr.Code, rr.Body.String())
	}
	var run map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&run)
	if run["policy_name"] != "policy-to-delete" {
		t.Errorf("GET run after delete: policy_name = %q, want policy-to-delete", run["policy_name"])
	}

	// GET /admin/evals (list) — name must still be present.
	rr = doEvalRequest(t, api, http.MethodGet, "/admin/evals", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var runs []map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&runs)
	if len(runs) != 1 {
		t.Fatalf("expected 1 run in list, got %d", len(runs))
	}
	if runs[0]["policy_name"] != "policy-to-delete" {
		t.Errorf("list run after delete: policy_name = %q, want policy-to-delete", runs[0]["policy_name"])
	}
}

// TestEvalRun_TotalEntriesSetOnCreate verifies that total_entries is populated
// on the run immediately after creation (before eval completes).
func TestEvalRun_TotalEntriesSetOnCreate(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())
	policy, _ := policyStore.Create("total-entries-policy", "allow all", "", "", "", "", nil)

	seedAuditEntry(t, "GET", "/api/1", "approved", policy.ID)
	seedAuditEntry(t, "GET", "/api/2", "approved", policy.ID)
	seedAuditEntry(t, "GET", "/api/3", "approved", policy.ID)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
		"filter":    map[string]interface{}{"limit": 10},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)

	// total_entries must be set in the creation response
	te, _ := created["total_entries"].(float64)
	if int(te) != 3 {
		t.Errorf("created run total_entries = %v, want 3", created["total_entries"])
	}

	// Also verify it's present once the run completes
	run := pollRunUntilDone(t, api, created["id"].(string), 5*time.Second)
	if te2, _ := run["total_entries"].(float64); int(te2) != 3 {
		t.Errorf("completed run total_entries = %v, want 3", run["total_entries"])
	}
}

// TestEvalRun_Cancel_StopsRun verifies POST /admin/evals/{id}/cancel cancels a
// running eval and transitions it to "failed". Uses a blocking judge to ensure
// the run is still active when the cancel request arrives.
func TestEvalRun_Cancel_StopsRun(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	// Judge blocks until released — keeps goroutines occupied so the run stays
	// "running" long enough for us to cancel it.
	blocked := make(chan struct{})
	blockingJudge := judge.NewLLMJudge(&llm.TestAdapter{Fn: func(_ llm.Request) (llm.Response, error) {
		<-blocked
		return llm.Response{Text: `{"decision":"ALLOW","reason":"ok"}`}, nil
	}})

	api, policyStore := newEvalAPI(t, blockingJudge)
	policy, _ := policyStore.Create("cancel-test-policy", "allow all", "", "", "", "", nil)

	// Seed more entries than the semaphore capacity (25) so at least one entry
	// is waiting on the semaphore when we cancel.
	for i := 0; i < 30; i++ {
		seedAuditEntry(t, "GET", fmt.Sprintf("/api/%d", i), "approved", policy.ID)
	}

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)

	// Wait for the run to transition to "running".
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rr := doEvalRequest(t, api, http.MethodGet, "/admin/evals/"+runID, nil)
		var run map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&run)
		if run["status"] == "running" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Cancel the run.
	rr = doEvalRequest(t, api, http.MethodPost, "/admin/evals/"+runID+"/cancel", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST cancel: %d: %s", rr.Code, rr.Body.String())
	}

	// Unblock the judge so the in-flight goroutines can finish.
	close(blocked)

	run := pollRunUntilDone(t, api, runID, 5*time.Second)
	if run["status"] != "canceled" {
		t.Errorf("status = %v, want canceled after cancel", run["status"])
	}
}

// TestEvalRun_Cancel_NotRunning_Returns409 verifies that canceling a run that
// has already completed returns 409 Conflict.
func TestEvalRun_Cancel_NotRunning_Returns409(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	api, policyStore := newEvalAPI(t, newAllowJudge())
	policy, _ := policyStore.Create("cancel-done-policy", "allow all", "", "", "", "", nil)
	seedAuditEntry(t, "GET", "/api/1", "approved", policy.ID)

	rr := doEvalRequest(t, api, http.MethodPost, "/admin/evals", map[string]interface{}{
		"policy_id": policy.ID,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/evals: %d: %s", rr.Code, rr.Body.String())
	}
	var created map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&created)
	runID := created["id"].(string)

	pollRunUntilDone(t, api, runID, 5*time.Second)

	rr = doEvalRequest(t, api, http.MethodPost, "/admin/evals/"+runID+"/cancel", nil)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 for cancel of completed run, got %d: %s", rr.Code, rr.Body.String())
	}
}
