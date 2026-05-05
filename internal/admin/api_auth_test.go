package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// --- minimal stubs ---

type stubValidator struct {
	// token -> (userID, role, ok)
	tokens map[string]stubUser
}

type stubUser struct {
	userID string
	role   string
}

func (v *stubValidator) GetUserByWebToken(token string) (string, string, bool) {
	u, ok := v.tokens[token]
	return u.userID, u.role, ok
}

type stubAuditReader struct{}

func (r *stubAuditReader) Add(_ types.AuditEntry)                          {}
func (r *stubAuditReader) Query(_ AuditFilter) []types.AuditEntry          { return nil }
func (r *stubAuditReader) QuerySummaries(_ AuditFilter) []types.AuditEntry { return nil }
func (r *stubAuditReader) QueryBatched(_ context.Context, _ AuditFilter, _ int, _ func([]types.AuditEntry) error) error {
	return nil
}
func (r *stubAuditReader) Count(_ context.Context, _ AuditFilter) (int, error) { return 0, nil }
func (r *stubAuditReader) UpdateResponse(_ string, _ int, _ http.Header, _, _ string, _ int64) error {
	return nil
}
func (r *stubAuditReader) GetEntry(_ string) (*types.AuditEntry, error) {
	return nil, fmt.Errorf("not found")
}
func (r *stubAuditReader) GetPolicyStats(_ string) (*PolicyStats, error) {
	return &PolicyStats{ByDecision: map[string]*PolicyDecisionStats{}}, nil
}

// capturingAuditReader records the last filter passed to QuerySummaries.
type capturingAuditReader struct {
	lastFilter AuditFilter
}

func (r *capturingAuditReader) Add(_ types.AuditEntry) {}
func (r *capturingAuditReader) Query(f AuditFilter) []types.AuditEntry {
	r.lastFilter = f
	return nil
}
func (r *capturingAuditReader) QuerySummaries(f AuditFilter) []types.AuditEntry {
	r.lastFilter = f
	return nil
}
func (r *capturingAuditReader) QueryBatched(_ context.Context, _ AuditFilter, _ int, _ func([]types.AuditEntry) error) error {
	return nil
}
func (r *capturingAuditReader) Count(_ context.Context, _ AuditFilter) (int, error) { return 0, nil }
func (r *capturingAuditReader) UpdateResponse(_ string, _ int, _ http.Header, _, _ string, _ int64) error {
	return nil
}
func (r *capturingAuditReader) GetEntry(_ string) (*types.AuditEntry, error) {
	return nil, fmt.Errorf("not found")
}
func (r *capturingAuditReader) GetPolicyStats(_ string) (*PolicyStats, error) {
	return &PolicyStats{ByDecision: map[string]*PolicyDecisionStats{}}, nil
}

type stubUserStore struct{}

func (s *stubUserStore) ListUsers() ([]UserSummary, error) { return nil, nil }
func (s *stubUserStore) GetUser(id string) (*UserDetail, error) {
	role := "user"
	if strings.Contains(id, "mgr") || strings.Contains(id, "manager") || strings.Contains(id, "admin") {
		role = "manager"
	}
	return &UserDetail{ID: id, Role: role, Channels: []UserChannelInfo{}, Managers: []ManagerAssignment{}}, nil
}
func (s *stubUserStore) CreateUser(req CreateUserRequest) (*UserDetail, error) {
	role := "user"
	if req.Role != nil {
		role = *req.Role
	}
	return &UserDetail{ID: req.ID, Role: role, Channels: []UserChannelInfo{}, Managers: []ManagerAssignment{}}, nil
}
func (s *stubUserStore) UpdateUser(id string, req UpdateUserRequest) (*UserDetail, error) {
	return &UserDetail{ID: id, Channels: []UserChannelInfo{}, Managers: []ManagerAssignment{}}, nil
}
func (s *stubUserStore) DeleteUser(id string) error                          { return nil }
func (s *stubUserStore) AssignManager(botID, managerID string) error          { return nil }
func (s *stubUserStore) UnassignManager(botID, managerID string) error        { return nil }
func (s *stubUserStore) ListManagers(botID string) ([]ManagerAssignment, error) {
	return []ManagerAssignment{}, nil
}
func (s *stubUserStore) ListManagedBots(managerID string) ([]ManagerAssignment, error) {
	return []ManagerAssignment{}, nil
}
func (s *stubUserStore) ListUsersForManager(managerID string) ([]UserSummary, error) {
	return []UserSummary{}, nil
}
func (s *stubUserStore) IsManagerOf(managerID, botID string) (bool, error) { return false, nil }

// --- helpers ---

const (
	adminToken    = "admin-token"
	managerToken  = "manager-token"
	nonAdminToken = "user-token"
)

func newTestAPI() *API {
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken:    {userID: "admin@example.com", role: "admin"},
			managerToken:  {userID: "manager@example.com", role: "manager"},
			nonAdminToken: {userID: "user@example.com", role: "user"},
		},
	}
	api := NewAPI(
		&stubAuditReader{},
		notifications.NewDispatcher(),
		notifications.NewSSEChannel("web"),
		validator,
		&stubUserStore{},
	)
	return api
}

func doRequest(t *testing.T, api *API, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	mux.ServeHTTP(rr, req)
	return rr
}

// --- tests ---

// TestAdminRoutes_AuthEnforcement verifies that every admin-only route:
//   - returns 401 when no token is provided
//   - returns 403 when a valid but non-admin token is provided
//   - passes auth (not 401/403) when an admin token is provided
func TestAdminRoutes_AuthEnforcement(t *testing.T) {
	api := newTestAPI()

	type routeCase struct {
		method string
		path   string
		body   string
	}

	routes := []routeCase{
		{http.MethodGet, "/admin/audit", ""},
		// LLM policy routes
		{http.MethodGet, "/admin/llm-policies", ""},
		{http.MethodPost, "/admin/llm-policies", `{"name":"p","prompt":"","provider":"","model":""}`},
		{http.MethodGet, "/admin/llm-policies/pol-1", ""},
		{http.MethodGet, "/admin/llm-policies/pol-1/stats", ""},
		{http.MethodPost, "/admin/llm-policies/pol-1/fork", `{"name":"fork"}`},
		{http.MethodDelete, "/admin/llm-policies/pol-1", ""},
		// User management routes
		{http.MethodGet, "/admin/users", ""},
		{http.MethodPost, "/admin/users", `{"id":"test@x.com"}`},
		{http.MethodGet, "/admin/users/test%40x.com", ""},
		{http.MethodPut, "/admin/users/test%40x.com", `{}`},
		{http.MethodDelete, "/admin/users/test%40x.com", ""},
		// Eval routes
		{http.MethodPost, "/admin/evals", `{"policy_id":"pol-1"}`},
		{http.MethodGet, "/admin/evals", ""},
		{http.MethodGet, "/admin/evals/run-1", ""},
		{http.MethodGet, "/admin/evals/run-1/results", ""},
		// Audit routes
		{http.MethodGet, "/admin/audit/entry-1", ""},
		{http.MethodPut, "/admin/audit/entry-1/label", `{"decision":"ALLOW"}`},
		{http.MethodDelete, "/admin/audit/entry-1/label", ""},
	}

	for _, tc := range routes {
		t.Run(tc.method+"_"+tc.path+"/no_token", func(t *testing.T) {
			rr := doRequest(t, api, tc.method, tc.path, "", tc.body)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d", rr.Code)
			}
		})

		t.Run(tc.method+"_"+tc.path+"/non_admin", func(t *testing.T) {
			rr := doRequest(t, api, tc.method, tc.path, nonAdminToken, tc.body)
			if rr.Code != http.StatusForbidden {
				t.Errorf("expected 403, got %d", rr.Code)
			}
		})

		t.Run(tc.method+"_"+tc.path+"/admin", func(t *testing.T) {
			rr := doRequest(t, api, tc.method, tc.path, adminToken, tc.body)
			if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
				t.Errorf("admin token should pass auth, got %d", rr.Code)
			}
		})
	}
}

// TestSSERoute_AuthEnforcement tests the SSE endpoint auth in isolation
// (without blocking on the stream).
func TestSSERoute_AuthEnforcement(t *testing.T) {
	api := newTestAPI()

	t.Run("no_token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/events", nil)
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("non_admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/events", nil)
		req.Header.Set("Authorization", "Bearer "+nonAdminToken)
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rr.Code)
		}
	})
}

// TestAuditLog_PolicyIDFilter verifies that ?policy_id= is forwarded to AuditFilter.PolicyID.
func TestAuditLog_PolicyIDFilter(t *testing.T) {
	cap := &capturingAuditReader{}
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken: {userID: "admin@example.com", role: "admin"},
		},
	}
	api := NewAPI(
		cap,
		notifications.NewDispatcher(),
		notifications.NewSSEChannel("web"),
		validator,
		&stubUserStore{},
	)

	rr := doRequest(t, api, http.MethodGet, "/admin/audit?policy_id=llmpol_abc", adminToken, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if cap.lastFilter.PolicyID != "llmpol_abc" {
		t.Errorf("filter.PolicyID = %q, want %q", cap.lastFilter.PolicyID, "llmpol_abc")
	}
}

// TestPublicRoutes verifies that health and me do not require admin.
func TestPublicRoutes(t *testing.T) {
	api := newTestAPI()

	t.Run("health_no_token", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/health", "", "")
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rr.Code)
		}
	})

	t.Run("me_no_token", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me", "", "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 without token, got %d", rr.Code)
		}
	})

	t.Run("me_non_admin_token", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me", nonAdminToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("me should return 200 for any valid token, got %d", rr.Code)
		}
	})

	t.Run("me_admin_token", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me", adminToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("me should return 200 for admin token, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `"is_admin":true`) {
			t.Errorf("expected is_admin:true in response, got: %s", body)
		}
	})

	t.Run("me_non_admin_returns_is_admin_false", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me", nonAdminToken, "")
		body := rr.Body.String()
		if !strings.Contains(body, `"is_admin":false`) {
			t.Errorf("expected is_admin:false for non-admin user, got: %s", body)
		}
	})
}

// --- Cookie security tests ---

// findCookie returns the first Set-Cookie matching the given name from the response.
func findCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestLogin_SetsCookieFlags verifies that POST /admin/login sets an auth
// cookie with HttpOnly, SameSite=Strict, and conditionally Secure.
func TestLogin_SetsCookieFlags(t *testing.T) {
	api := newTestAPI()

	// Helper to POST /admin/login.
	doLogin := func(t *testing.T, token string) *httptest.ResponseRecorder {
		t.Helper()
		body := fmt.Sprintf(`{"token":%q}`, token)
		req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)
		return rr
	}

	t.Run("valid_token_sets_httponly_samesite", func(t *testing.T) {
		rr := doLogin(t, adminToken)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}
		c := findCookie(rr, "token")
		if c == nil {
			t.Fatal("expected a 'token' Set-Cookie header")
		}
		if !c.HttpOnly {
			t.Error("cookie must have HttpOnly flag")
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie SameSite = %v, want Strict", c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("cookie Path = %q, want /", c.Path)
		}
		if c.Value != adminToken {
			t.Errorf("cookie Value = %q, want %q", c.Value, adminToken)
		}
		if c.MaxAge <= 0 {
			t.Errorf("cookie MaxAge = %d, want positive", c.MaxAge)
		}
	})

	t.Run("secure_flag_off_by_default", func(t *testing.T) {
		rr := doLogin(t, adminToken)
		c := findCookie(rr, "token")
		if c == nil {
			t.Fatal("expected a 'token' Set-Cookie header")
		}
		if c.Secure {
			t.Error("cookie Secure should be false when secureCookie is not set")
		}
	})

	t.Run("secure_flag_on_when_configured", func(t *testing.T) {
		secureAPI := newTestAPI()
		secureAPI.SetSecureCookie(true)

		body := fmt.Sprintf(`{"token":%q}`, adminToken)
		req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		secureAPI.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)

		c := findCookie(rr, "token")
		if c == nil {
			t.Fatal("expected a 'token' Set-Cookie header")
		}
		if !c.Secure {
			t.Error("cookie Secure should be true when secureCookie is enabled")
		}
	})

	t.Run("invalid_token_returns_401_no_cookie", func(t *testing.T) {
		rr := doLogin(t, "invalid-token")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
		c := findCookie(rr, "token")
		if c != nil {
			t.Error("no cookie should be set for invalid tokens")
		}
	})

	t.Run("empty_token_returns_400", func(t *testing.T) {
		rr := doLogin(t, "")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("response_includes_user_identity", func(t *testing.T) {
		rr := doLogin(t, adminToken)
		body := rr.Body.String()
		if !strings.Contains(body, `"user_id"`) {
			t.Error("response should include user_id")
		}
		if !strings.Contains(body, `"is_admin"`) {
			t.Error("response should include is_admin")
		}
	})
}

// TestLogout_ClearsCookie verifies POST /admin/logout clears the auth cookie.
func TestLogout_ClearsCookie(t *testing.T) {
	api := newTestAPI()

	t.Run("clears_cookie_with_negative_maxage", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		c := findCookie(rr, "token")
		if c == nil {
			t.Fatal("expected a 'token' Set-Cookie header to clear the cookie")
		}
		if c.MaxAge != -1 {
			t.Errorf("cookie MaxAge = %d, want -1 (delete)", c.MaxAge)
		}
		if !c.HttpOnly {
			t.Error("even the deletion cookie should be HttpOnly")
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Error("even the deletion cookie should be SameSite=Strict")
		}
	})

	t.Run("logout_only_accepts_POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/logout", nil)
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

// TestCookieAuth_ExtractWebToken verifies that extractWebToken reads from
// the cookie, allowing the HttpOnly cookie to be used for SSE and other endpoints.
func TestCookieAuth_ExtractWebToken(t *testing.T) {
	api := newTestAPI()

	t.Run("cookie_auth_works_for_admin_endpoints", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
		req.AddCookie(&http.Cookie{Name: "token", Value: adminToken})
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)

		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
			t.Errorf("cookie-based auth should work, got %d", rr.Code)
		}
	})

	t.Run("bearer_header_takes_priority_over_cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.AddCookie(&http.Cookie{Name: "token", Value: "stale-cookie-value"})
		rr := httptest.NewRecorder()
		mux := http.NewServeMux()
		api.RegisterRoutes(mux)
		mux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Bearer header should take priority, got %d", rr.Code)
		}
	})
}

// TestManagerRole_AuthEnforcement verifies that manager tokens are rejected by
// admin-only endpoints but can access /admin/me.
func TestManagerRole_AuthEnforcement(t *testing.T) {
	api := newTestAPI()

	adminOnlyRoutes := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/admin/audit", ""},
		{http.MethodGet, "/admin/llm-policies", ""},
		{http.MethodGet, "/admin/evals", ""},
	}

	for _, tc := range adminOnlyRoutes {
		t.Run("manager_forbidden/"+tc.method+"_"+tc.path, func(t *testing.T) {
			rr := doRequest(t, api, tc.method, tc.path, managerToken, tc.body)
			if rr.Code != http.StatusForbidden {
				t.Errorf("manager should get 403 on admin-only route, got %d", rr.Code)
			}
		})
	}

	t.Run("manager_can_access_me", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me", managerToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("manager should access /admin/me, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `"role":"manager"`) {
			t.Errorf("expected role:manager in response, got: %s", body)
		}
		if !strings.Contains(body, `"is_admin":false`) {
			t.Errorf("expected is_admin:false for manager, got: %s", body)
		}
	})

	t.Run("manager_can_login", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/login", "", `{"token":"`+managerToken+`"}`)
		if rr.Code != http.StatusOK {
			t.Errorf("manager should be able to login, got %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, `"role":"manager"`) {
			t.Errorf("login should return role:manager, got: %s", body)
		}
	})
}

// TestManagerUserList verifies that managers see a filtered user list and can create bot users.
func TestManagerUserList(t *testing.T) {
	api := newTestAPI()

	t.Run("manager_gets_200_on_user_list", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/users", managerToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("manager should access GET /admin/users, got %d", rr.Code)
		}
	})

	t.Run("manager_can_create_bot_user", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users", managerToken, `{"id":"newbot@y.com"}`)
		if rr.Code != http.StatusCreated {
			t.Errorf("manager should create bot users, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("manager_cannot_create_admin_user", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users", managerToken, `{"id":"x@y.com","role":"admin"}`)
		if rr.Code != http.StatusForbidden {
			t.Errorf("manager should not create admin users, got %d", rr.Code)
		}
	})

	t.Run("manager_cannot_create_manager_user", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users", managerToken, `{"id":"x@y.com","role":"manager"}`)
		if rr.Code != http.StatusForbidden {
			t.Errorf("manager should not create manager users, got %d", rr.Code)
		}
	})
}

// TestManagerBotAssignment_AuthEnforcement verifies auth on manager assignment endpoints.
func TestManagerBotAssignment_AuthEnforcement(t *testing.T) {
	api := newTestAPI()

	t.Run("admin_can_assign_manager", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users/bot%40x.com/managers", adminToken, `{"manager_id":"mgr@x.com"}`)
		if rr.Code != http.StatusCreated {
			t.Errorf("admin should assign managers, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("manager_cannot_assign_manager", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users/bot%40x.com/managers", managerToken, `{"manager_id":"mgr@x.com"}`)
		if rr.Code != http.StatusForbidden {
			t.Errorf("manager should not assign managers, got %d", rr.Code)
		}
	})

	t.Run("no_token_returns_401", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users/bot%40x.com/managers", "", `{"manager_id":"mgr@x.com"}`)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("no token should return 401, got %d", rr.Code)
		}
	})

	t.Run("admin_can_list_managers", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/users/bot%40x.com/managers", adminToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("admin should list managers, got %d", rr.Code)
		}
	})

	t.Run("unrelated_manager_cannot_list_managers", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/users/bot%40x.com/managers", managerToken, "")
		if rr.Code != http.StatusForbidden {
			t.Errorf("unrelated manager should get 403, got %d", rr.Code)
		}
	})

	t.Run("admin_can_unassign_manager", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodDelete, "/admin/users/bot%40x.com/managers/mgr%40x.com", adminToken, "")
		// May be 404 (assignment not found in stub) but should not be 401/403
		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden {
			t.Errorf("admin should pass auth on unassign, got %d", rr.Code)
		}
	})

	t.Run("manager_cannot_unassign", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodDelete, "/admin/users/bot%40x.com/managers/mgr%40x.com", managerToken, "")
		if rr.Code != http.StatusForbidden {
			t.Errorf("manager should not unassign, got %d", rr.Code)
		}
	})
}

// TestAssignManager_RoleValidation verifies that only users with manager/admin role can be assigned.
func TestAssignManager_RoleValidation(t *testing.T) {
	userRoleStore := &roleAwareStubUserStore{
		roles: map[string]string{
			"bot@x.com":     "user",
			"regular@x.com": "user",
			"mgr@x.com":     "manager",
		},
	}
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken: {userID: "admin@example.com", role: "admin"},
		},
	}
	api := NewAPI(
		&stubAuditReader{},
		notifications.NewDispatcher(),
		notifications.NewSSEChannel("web"),
		validator,
		userRoleStore,
	)

	t.Run("reject_user_role_as_manager", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users/bot%40x.com/managers", adminToken, `{"manager_id":"regular@x.com"}`)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("should reject user-role as manager, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("accept_manager_role", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users/bot%40x.com/managers", adminToken, `{"manager_id":"mgr@x.com"}`)
		if rr.Code != http.StatusCreated {
			t.Errorf("should accept manager-role, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("reject_nonexistent_manager", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPost, "/admin/users/bot%40x.com/managers", adminToken, `{"manager_id":"ghost@x.com"}`)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("should reject nonexistent manager, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// roleAwareStubUserStore returns users with configurable roles for validation tests.
type roleAwareStubUserStore struct {
	stubUserStore
	roles       map[string]string
	assignments map[string][]string // managerID -> []botID
}

func (s *roleAwareStubUserStore) GetUser(id string) (*UserDetail, error) {
	role, exists := s.roles[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return &UserDetail{ID: id, Role: role, Channels: []UserChannelInfo{}, Managers: []ManagerAssignment{}}, nil
}

func (s *roleAwareStubUserStore) IsManagerOf(managerID, botID string) (bool, error) {
	if s.assignments == nil {
		return false, nil
	}
	for _, b := range s.assignments[managerID] {
		if b == botID {
			return true, nil
		}
	}
	return false, nil
}

// TestMeBots_AuthEnforcement verifies /admin/me/bots requires at least manager role.
func TestMeBots_AuthEnforcement(t *testing.T) {
	api := newTestAPI()

	t.Run("admin_can_access", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me/bots", adminToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("admin should access /admin/me/bots, got %d", rr.Code)
		}
	})

	t.Run("manager_can_access", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me/bots", managerToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("manager should access /admin/me/bots, got %d", rr.Code)
		}
	})

	t.Run("user_gets_403", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me/bots", nonAdminToken, "")
		if rr.Code != http.StatusForbidden {
			t.Errorf("user should get 403 on /admin/me/bots, got %d", rr.Code)
		}
	})

	t.Run("no_token_gets_401", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/me/bots", "", "")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("no token should return 401, got %d", rr.Code)
		}
	})
}

// TestManagerGetUserDetail verifies that managers can GET detail of their
// assigned bots but not unassigned ones.
func TestManagerGetUserDetail(t *testing.T) {
	store := &roleAwareStubUserStore{
		roles: map[string]string{
			"bot@x.com":     "user",
			"other@x.com":   "user",
			"mgr@x.com":     "manager",
		},
		assignments: map[string][]string{
			"mgr@x.com": {"bot@x.com"},
		},
	}
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken:   {userID: "admin@example.com", role: "admin"},
			managerToken: {userID: "mgr@x.com", role: "manager"},
		},
	}
	api := NewAPI(
		&stubAuditReader{},
		notifications.NewDispatcher(),
		notifications.NewSSEChannel("web"),
		validator,
		store,
	)

	t.Run("manager_can_view_assigned_bot", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/users/bot%40x.com", managerToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("manager should view assigned bot, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("manager_cannot_view_unassigned_bot", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/users/other%40x.com", managerToken, "")
		if rr.Code != http.StatusForbidden {
			t.Errorf("manager should not view unassigned bot, got %d", rr.Code)
		}
	})

	t.Run("manager_cannot_update_bot", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodPut, "/admin/users/bot%40x.com", managerToken, `{"role":"admin"}`)
		if rr.Code != http.StatusForbidden {
			t.Errorf("manager should not update bot, got %d", rr.Code)
		}
	})

	t.Run("manager_cannot_delete_bot", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodDelete, "/admin/users/bot%40x.com", managerToken, "")
		if rr.Code != http.StatusForbidden {
			t.Errorf("manager should not delete bot, got %d", rr.Code)
		}
	})

	t.Run("admin_can_view_any_user", func(t *testing.T) {
		rr := doRequest(t, api, http.MethodGet, "/admin/users/other%40x.com", adminToken, "")
		if rr.Code != http.StatusOK {
			t.Errorf("admin should view any user, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestUnknownRole_IsForbidden verifies that an unrecognized role value is
// rejected by requireRole.
func TestUnknownRole_IsForbidden(t *testing.T) {
	validator := &stubValidator{
		tokens: map[string]stubUser{
			"bad-token": {userID: "bad@example.com", role: "superadmin"},
		},
	}
	api := NewAPI(
		&stubAuditReader{},
		notifications.NewDispatcher(),
		notifications.NewSSEChannel("web"),
		validator,
		&stubUserStore{},
	)

	rr := doRequest(t, api, http.MethodGet, "/admin/me", "bad-token", "")
	if rr.Code != http.StatusOK {
		t.Logf("unknown role on /admin/me (no min role required) got %d — OK since me doesn't use requireRole", rr.Code)
	}

	rr = doRequest(t, api, http.MethodGet, "/admin/users", "bad-token", "")
	if rr.Code != http.StatusForbidden {
		t.Errorf("unknown role should be forbidden on admin endpoints, got %d", rr.Code)
	}
}
