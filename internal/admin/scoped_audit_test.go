package admin

import (
	"net/http"
	"testing"
	"time"

	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

func newScopedAuditAPI(t *testing.T) (*API, *PGAuditReader, *PGUserStore) {
	t.Helper()
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken:   {userID: "admin@example.com", role: "admin"},
			managerToken: {userID: "manager@example.com", role: "manager"},
		},
	}
	reader := NewPGAuditReader(testPool)
	userStore := NewPGUserStore(testPool)
	api := NewAPI(
		reader,
		notifications.NewDispatcher(), notifications.NewSSEChannel("web"),
		validator, userStore,
	)
	return api, reader, userStore
}

func TestScopedAudit_ManagerSeesOnlyManagedBots(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, userStore := newScopedAuditAPI(t)

	mgrRole := "manager"
	userStore.CreateUser(CreateUserRequest{ID: "admin@example.com", IsAdmin: true})
	userStore.CreateUser(CreateUserRequest{ID: "manager@example.com", Role: &mgrRole})
	userStore.CreateUser(CreateUserRequest{ID: "bot-a@example.com"})
	userStore.CreateUser(CreateUserRequest{ID: "bot-b@example.com"})

	userStore.AssignManager("bot-a@example.com", "manager@example.com")

	reader.Add(types.AuditEntry{UserID: "bot-a@example.com", Method: "GET", URL: "https://api.example.com/a", Decision: "ALLOW", Timestamp: time.Now()})
	reader.Add(types.AuditEntry{UserID: "bot-b@example.com", Method: "GET", URL: "https://api.example.com/b", Decision: "DENY", Timestamp: time.Now()})

	rr := doRequest(t, api, http.MethodGet, "/admin/audit", managerToken, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("manager audit: got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Entries []types.AuditEntry `json:"entries"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Entries) != 1 {
		t.Fatalf("manager should see 1 entry, got %d", len(resp.Entries))
	}
	if resp.Entries[0].UserID != "bot-a@example.com" {
		t.Errorf("expected bot-a entry, got user_id=%s", resp.Entries[0].UserID)
	}

	rr = doRequest(t, api, http.MethodGet, "/admin/audit", adminToken, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin audit: got %d", rr.Code)
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Entries) != 2 {
		t.Errorf("admin should see 2 entries, got %d", len(resp.Entries))
	}
}

func TestScopedAudit_ManagerCanFilterToManagedBot(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, userStore := newScopedAuditAPI(t)

	mgrRole := "manager"
	userStore.CreateUser(CreateUserRequest{ID: "manager@example.com", Role: &mgrRole})
	userStore.CreateUser(CreateUserRequest{ID: "bot-a@example.com"})
	userStore.AssignManager("bot-a@example.com", "manager@example.com")

	reader.Add(types.AuditEntry{UserID: "bot-a@example.com", Method: "POST", URL: "https://api.example.com/x", Decision: "DENY", Timestamp: time.Now()})

	rr := doRequest(t, api, http.MethodGet, "/admin/audit?user_id=bot-a@example.com", managerToken, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("manager filter to managed bot: got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Entries []types.AuditEntry `json:"entries"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(resp.Entries))
	}
}

func TestScopedAudit_ManagerCannotFilterToUnmanagedBot(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _, userStore := newScopedAuditAPI(t)

	mgrRole := "manager"
	userStore.CreateUser(CreateUserRequest{ID: "manager@example.com", Role: &mgrRole})
	userStore.CreateUser(CreateUserRequest{ID: "bot-a@example.com"})
	userStore.CreateUser(CreateUserRequest{ID: "bot-b@example.com"})
	userStore.AssignManager("bot-a@example.com", "manager@example.com")

	rr := doRequest(t, api, http.MethodGet, "/admin/audit?user_id=bot-b@example.com", managerToken, "")
	if rr.Code != http.StatusForbidden {
		t.Errorf("manager filtering to unmanaged bot should be 403, got %d", rr.Code)
	}
}

func TestScopedAudit_ManagerWithNoBotsSeesNothing(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, reader, userStore := newScopedAuditAPI(t)

	mgrRole := "manager"
	userStore.CreateUser(CreateUserRequest{ID: "manager@example.com", Role: &mgrRole})
	userStore.CreateUser(CreateUserRequest{ID: "bot-a@example.com"})

	reader.Add(types.AuditEntry{UserID: "bot-a@example.com", Method: "GET", URL: "https://api.example.com/a", Decision: "ALLOW", Timestamp: time.Now()})

	rr := doRequest(t, api, http.MethodGet, "/admin/audit", managerToken, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("manager audit with no bots: got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Entries []types.AuditEntry `json:"entries"`
	}
	decodeJSON(t, rr, &resp)
	if len(resp.Entries) != 0 {
		t.Errorf("manager with no bots should see 0 entries, got %d", len(resp.Entries))
	}
}

func TestScopedAudit_UserRoleCannotAccessAudit(t *testing.T) {
	api := newTestAPI()
	rr := doRequest(t, api, http.MethodGet, "/admin/audit", nonAdminToken, "")
	if rr.Code != http.StatusForbidden {
		t.Errorf("user role should get 403 on audit, got %d", rr.Code)
	}
}
