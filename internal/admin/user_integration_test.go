package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brexhq/CrabTrap/internal/llmpolicy"
	"github.com/brexhq/CrabTrap/internal/notifications"
)

// newUserAPI wires up an admin API backed by the real PG user store.
func newUserAPI(t *testing.T) *API {
	t.Helper()
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken: {userID: "admin@example.com", role: "admin"},
		},
	}
	api := NewAPI(
		&stubAuditReader{},
		notifications.NewDispatcher(), notifications.NewSSEChannel("web"),
		validator, NewPGUserStore(testPool),
	)
	api.SetLLMPolicyStore(llmpolicy.NewPGStore(testPool))
	return api
}

// doAdminRequest fires a request with the admin token.
func doAdminRequest(t *testing.T, api *API, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, api, method, path, adminToken, body)
}

// decodeJSON decodes the recorder body into v.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(v); err != nil {
		t.Fatalf("decodeJSON: %v (body: %s)", err, rr.Body.String())
	}
}

// --- GET /admin/users ---

func TestUsers_List(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"alice@example.com","is_admin":true}`)
	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"bob@example.com","is_admin":false}`)

	rr := doAdminRequest(t, api, http.MethodGet, "/admin/users", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/users: got %d: %s", rr.Code, rr.Body.String())
	}
	var users []UserSummary
	decodeJSON(t, rr, &users)
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

// --- POST /admin/users ---

func TestUsers_Create_Returns201(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	rr := doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"carol@example.com","is_admin":false}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /admin/users: got %d: %s", rr.Code, rr.Body.String())
	}
	var detail UserDetail
	decodeJSON(t, rr, &detail)
	if detail.ID != "carol@example.com" {
		t.Errorf("id = %q, want carol@example.com", detail.ID)
	}
	if detail.IsAdmin {
		t.Error("expected is_admin=false")
	}
	// CreateUser always provisions a gateway_auth channel.
	if len(detail.Channels) == 0 {
		t.Error("expected at least one channel (gateway_auth) to be provisioned")
	}
}

func TestUsers_Create_MissingID_Returns400(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	rr := doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"is_admin":false}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- GET /admin/users/{id} ---

func TestUsers_Get_Returns200(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"dave@example.com","is_admin":false,"web_token":"tok-abc"}`)

	rr := doAdminRequest(t, api, http.MethodGet, "/admin/users/dave%40example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /admin/users/{id}: got %d: %s", rr.Code, rr.Body.String())
	}
	var detail UserDetail
	decodeJSON(t, rr, &detail)
	if detail.ID != "dave@example.com" {
		t.Errorf("id = %q, want dave@example.com", detail.ID)
	}
	// Should have web + gateway_auth channels.
	channelTypes := map[string]bool{}
	for _, ch := range detail.Channels {
		channelTypes[ch.ChannelType] = true
	}
	if !channelTypes["web"] {
		t.Error("expected web channel from web_token")
	}
	if !channelTypes["gateway_auth"] {
		t.Error("expected gateway_auth channel to be auto-provisioned")
	}
}

func TestUsers_Get_NotFound_Returns404(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	rr := doAdminRequest(t, api, http.MethodGet, "/admin/users/nobody%40example.com", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// --- PUT /admin/users/{id} ---

func TestUsers_Update_IsAdmin(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"eve@example.com","is_admin":false}`)

	rr := doAdminRequest(t, api, http.MethodPut, "/admin/users/eve%40example.com", `{"is_admin":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT /admin/users/{id}: got %d: %s", rr.Code, rr.Body.String())
	}
	var detail UserDetail
	decodeJSON(t, rr, &detail)
	if !detail.IsAdmin {
		t.Error("expected is_admin=true after update")
	}
}

func TestUsers_Update_LLMPolicyID(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"frank@example.com","is_admin":false}`)

	// Create a real policy so the FK is satisfied.
	policyStore := llmpolicy.NewPGStore(testPool)
	policy, _ := policyStore.Create("test-policy", "prompt", "", "", "", "", nil)

	rr := doAdminRequest(t, api, http.MethodPut, "/admin/users/frank%40example.com",
		`{"llm_policy_id":"`+policy.ID+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT llm_policy_id: got %d: %s", rr.Code, rr.Body.String())
	}
	var detail UserDetail
	decodeJSON(t, rr, &detail)
	if detail.LLMPolicyID != policy.ID {
		t.Errorf("llm_policy_id = %q, want %q", detail.LLMPolicyID, policy.ID)
	}
}

func TestUsers_Update_DraftPolicy_Returns400(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"draft-test@example.com","is_admin":false}`)

	policyStore := llmpolicy.NewPGStore(testPool)
	draft, _ := policyStore.Create("draft-policy", "prompt", "", "", "", "draft", nil)

	rr := doAdminRequest(t, api, http.MethodPut, "/admin/users/draft-test%40example.com",
		`{"llm_policy_id":"`+draft.ID+`"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("assigning draft policy: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestUsers_Update_PublishedPolicyAfterDraft_Returns200(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"publish-test@example.com","is_admin":false}`)

	policyStore := llmpolicy.NewPGStore(testPool)
	draft, _ := policyStore.Create("to-publish", "prompt", "", "", "", "draft", nil)
	published, _ := policyStore.Publish(draft.ID)

	rr := doAdminRequest(t, api, http.MethodPut, "/admin/users/publish-test%40example.com",
		`{"llm_policy_id":"`+published.ID+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("assigning published policy: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var detail UserDetail
	decodeJSON(t, rr, &detail)
	if detail.LLMPolicyID != published.ID {
		t.Errorf("llm_policy_id = %q, want %q", detail.LLMPolicyID, published.ID)
	}
}

func TestUsers_Update_ClearLLMPolicyID(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	policyStore := llmpolicy.NewPGStore(testPool)
	policy, _ := policyStore.Create("test-policy", "prompt", "", "", "", "", nil)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"grace@example.com","is_admin":false}`)
	doAdminRequest(t, api, http.MethodPut, "/admin/users/grace%40example.com",
		`{"llm_policy_id":"`+policy.ID+`"}`)

	// Clear it.
	rr := doAdminRequest(t, api, http.MethodPut, "/admin/users/grace%40example.com", `{"llm_policy_id":""}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT clear llm_policy_id: got %d: %s", rr.Code, rr.Body.String())
	}
	var detail UserDetail
	decodeJSON(t, rr, &detail)
	if detail.LLMPolicyID != "" {
		t.Errorf("expected llm_policy_id to be cleared, got %q", detail.LLMPolicyID)
	}
}

// --- DELETE /admin/users/{id} ---

func TestUsers_Delete(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"henry@example.com","is_admin":false}`)

	rr := doAdminRequest(t, api, http.MethodDelete, "/admin/users/henry%40example.com", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE /admin/users/{id}: got %d: %s", rr.Code, rr.Body.String())
	}

	rr = doAdminRequest(t, api, http.MethodGet, "/admin/users/henry%40example.com", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", rr.Code)
	}
}

// --- Structural tests (no DB required) ---

func TestUsers_MethodNotAllowed(t *testing.T) {
	api := newTestAPI()
	cases := []struct{ method, path string }{
		{http.MethodPatch, "/admin/users"},
	}
	for _, tc := range cases {
		rr := doAdminRequest(t, api, tc.method, tc.path, "")
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: expected 405, got %d", tc.method, tc.path, rr.Code)
		}
	}
}

func TestUsers_StoreNil_Returns503(t *testing.T) {
	validator := &stubValidator{tokens: map[string]stubUser{adminToken: {userID: "admin@example.com", role: "admin"}}}
	api := NewAPI(&stubAuditReader{},
		notifications.NewDispatcher(), notifications.NewSSEChannel("web"),
		validator, nil)

	for _, path := range []string{"/admin/users", "/admin/users/foo%40bar.com"} {
		rr := doAdminRequest(t, api, http.MethodGet, path, "")
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s with nil store: expected 503, got %d", path, rr.Code)
		}
	}
}

func TestUsers_ResponseContentType(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api := newUserAPI(t)

	doAdminRequest(t, api, http.MethodPost, "/admin/users", `{"id":"olivia@example.com"}`)

	paths := []struct{ method, path, body string }{
		{http.MethodGet, "/admin/users", ""},
		{http.MethodGet, "/admin/users/olivia%40example.com", ""},
		{http.MethodPut, "/admin/users/olivia%40example.com", `{}`},
	}
	for _, tc := range paths {
		rr := doAdminRequest(t, api, tc.method, tc.path, tc.body)
		ct := rr.Header().Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			t.Errorf("%s %s: expected application/json, got %q", tc.method, tc.path, ct)
		}
	}
}
