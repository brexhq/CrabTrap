package admin

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/brexhq/CrabTrap/internal/alerting"
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/pkg/types"
)

func newNotificationAPI(t *testing.T) (*API, *alerting.PGStore, *alerting.Service) {
	t.Helper()
	validator := &stubValidator{
		tokens: map[string]stubUser{
			adminToken:   {userID: "admin@example.com", role: "admin"},
			managerToken: {userID: "manager@example.com", role: "manager"},
			nonAdminToken: {userID: "user@example.com", role: "user"},
		},
	}
	userStore := NewPGUserStore(testPool)
	alertStore := alerting.NewPGStore(testPool)
	alertService := alerting.NewService(alertStore, alertStore, &mockSummarizer{}, 0)
	t.Cleanup(alertService.Stop)
	alertService.RegisterSender("slack", &mockSender{})

	dispatcher := notifications.NewDispatcher()
	api := NewAPI(
		NewPGAuditReader(testPool),
		dispatcher, notifications.NewSSEChannel("web"),
		validator, userStore,
	)
	api.SetNotificationStore(alertStore)
	api.SetAlertService(alertService)
	return api, alertStore, alertService
}

type mockSummarizer struct{}

func (m *mockSummarizer) Summarize(_ context.Context, botID string, denials []alerting.DenialInfo) (string, error) {
	return fmt.Sprintf("Bot %s had %d denials", botID, len(denials)), nil
}

type mockSender struct {
	mu       sync.Mutex
	messages []alerting.Message
}

func (m *mockSender) Send(_ context.Context, _ string, msg alerting.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockSender) Messages() []alerting.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]alerting.Message{}, m.messages...)
}

// --- CRUD tests ---

func TestNotificationChannels_CreateAndList(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _, _ := newNotificationAPI(t)

	mgrRole := "manager"
	doRequest(t, api, http.MethodPost, "/admin/users", adminToken, `{"id":"admin@example.com","role":"admin"}`)
	doRequest(t, api, http.MethodPost, "/admin/users", adminToken, `{"id":"manager@example.com","role":"`+mgrRole+`"}`)
	doRequest(t, api, http.MethodPost, "/admin/users", adminToken, `{"id":"bot@example.com"}`)
	doRequest(t, api, http.MethodPost, "/admin/users/bot@example.com/managers", adminToken, `{"manager_id":"manager@example.com"}`)

	// Manager creates channel
	rr := doRequest(t, api, http.MethodPost, "/admin/notification-channels", managerToken,
		`{"bot_id":"bot@example.com","channel_type":"slack","destination":"#alerts"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create channel: got %d: %s", rr.Code, rr.Body.String())
	}

	// Manager lists channels
	rr = doRequest(t, api, http.MethodGet, "/admin/notification-channels", managerToken, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list channels: got %d: %s", rr.Code, rr.Body.String())
	}
	var channels []alerting.NotificationChannel
	decodeJSON(t, rr, &channels)
	if len(channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(channels))
	}
	if channels[0].Destination != "#alerts" {
		t.Errorf("expected #alerts, got %s", channels[0].Destination)
	}
}

func TestNotificationChannels_UserRoleForbidden(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	api, _, _ := newNotificationAPI(t)

	rr := doRequest(t, api, http.MethodGet, "/admin/notification-channels", nonAdminToken, "")
	if rr.Code != http.StatusForbidden {
		t.Errorf("user role should get 403, got %d", rr.Code)
	}

	rr = doRequest(t, api, http.MethodPost, "/admin/notification-channels", nonAdminToken,
		`{"channel_type":"slack","destination":"#x"}`)
	if rr.Code != http.StatusForbidden {
		t.Errorf("user role should get 403 on create, got %d", rr.Code)
	}
}

func TestNotificationChannels_InvalidChannelType(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _, _ := newNotificationAPI(t)

	doRequest(t, api, http.MethodPost, "/admin/users", adminToken, `{"id":"admin@example.com","role":"admin"}`)

	rr := doRequest(t, api, http.MethodPost, "/admin/notification-channels", adminToken,
		`{"channel_type":"pagerduty","destination":"key123"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("unsupported channel_type should return 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestNotificationChannels_DeleteAndUpdate(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	api, _, _ := newNotificationAPI(t)

	doRequest(t, api, http.MethodPost, "/admin/users", adminToken, `{"id":"admin@example.com","role":"admin"}`)

	// Create
	rr := doRequest(t, api, http.MethodPost, "/admin/notification-channels", adminToken,
		`{"channel_type":"slack","destination":"#old"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: got %d", rr.Code)
	}
	var ch alerting.NotificationChannel
	decodeJSON(t, rr, &ch)

	// Update
	rr = doRequest(t, api, http.MethodPut, "/admin/notification-channels/"+ch.ID, adminToken,
		`{"destination":"#new"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: got %d: %s", rr.Code, rr.Body.String())
	}
	var updated alerting.NotificationChannel
	decodeJSON(t, rr, &updated)
	if updated.Destination != "#new" {
		t.Errorf("expected #new, got %s", updated.Destination)
	}

	// Delete
	rr = doRequest(t, api, http.MethodDelete, "/admin/notification-channels/"+ch.ID, adminToken, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("delete: got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify gone
	rr = doRequest(t, api, http.MethodGet, "/admin/notification-channels/"+ch.ID, adminToken, "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("should be 404 after delete, got %d", rr.Code)
	}
}

// --- Denial notification flow ---

func TestDenialAlert_NewPatternNotifies(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	_, alertStore, alertService := newNotificationAPI(t)

	userStore := NewPGUserStore(testPool)
	mgrRole := "manager"
	userStore.CreateUser(CreateUserRequest{ID: "manager@example.com", Role: &mgrRole})
	userStore.CreateUser(CreateUserRequest{ID: "bot@example.com"})
	userStore.AssignManager("bot@example.com", "manager@example.com")

	// Create notification channel directly in store
	ch := &alerting.NotificationChannel{
		OwnerID:     "manager@example.com",
		BotID:       "bot@example.com",
		ChannelType: "slack",
		Destination: "#test",
		Enabled:     true,
	}
	alertStore.CreateChannel(context.Background(), ch)

	// Replace sender with mock
	mock := &mockSender{}
	alertService.RegisterSender("slack", mock)

	// Simulate denial event
	dispatcher := notifications.NewDispatcher()
	dispatcher.RegisterChannel(alertService)
	dispatcher.Broadcast(notifications.Event{
		Type: notifications.EventAuditEntry,
		Data: &types.AuditEntry{
			UserID:   "bot@example.com",
			Method:   "POST",
			URL:      "https://api.github.com/repos/org/repo",
			Decision: "denied",
			LLMReason: "Policy blocks write access",
		},
	})

	// Wait for async dispatch
	alertService.FlushNow()

	msgs := mock.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(msgs))
	}
	if msgs[0].BotID != "bot@example.com" {
		t.Errorf("unexpected bot_id: %s", msgs[0].BotID)
	}
	if len(msgs[0].Denials) != 1 {
		t.Errorf("expected 1 denial in batch, got %d", len(msgs[0].Denials))
	}
}

func TestDenialAlert_SamePatternDeduped(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	_, alertStore, alertService := newNotificationAPI(t)

	userStore := NewPGUserStore(testPool)
	mgrRole := "manager"
	userStore.CreateUser(CreateUserRequest{ID: "manager@example.com", Role: &mgrRole})
	userStore.CreateUser(CreateUserRequest{ID: "bot@example.com"})
	userStore.AssignManager("bot@example.com", "manager@example.com")

	ch := &alerting.NotificationChannel{
		OwnerID:     "manager@example.com",
		BotID:       "bot@example.com",
		ChannelType: "slack",
		Destination: "#test",
		Enabled:     true,
	}
	alertStore.CreateChannel(context.Background(), ch)

	mock := &mockSender{}
	alertService.RegisterSender("slack", mock)

	dispatcher := notifications.NewDispatcher()
	dispatcher.RegisterChannel(alertService)

	event := notifications.Event{
		Type: notifications.EventAuditEntry,
		Data: &types.AuditEntry{
			UserID:   "bot@example.com",
			Method:   "POST",
			URL:      "https://api.github.com/repos/org/repo",
			Decision: "denied",
		},
	}

	// Send same event 5 times
	for i := 0; i < 5; i++ {
		dispatcher.Broadcast(event)
	}

	alertService.FlushNow()

	msgs := mock.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 notification (batched), got %d", len(msgs))
	}
	if len(msgs[0].Denials) != 5 {
		t.Errorf("expected 5 denials in batch, got %d", len(msgs[0].Denials))
	}
}

func TestClaimFlushableDenials_SecondCallEmpty(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)

	alertStore := alerting.NewPGStore(testPool)
	userStore := NewPGUserStore(testPool)
	ctx := context.Background()

	userStore.CreateUser(CreateUserRequest{ID: "bot@example.com"})

	// Buffer several denials for the same bot
	for i := 0; i < 3; i++ {
		err := alertStore.BufferDenial(ctx, "bot@example.com", "POST",
			fmt.Sprintf("https://api.github.com/repos/org/repo-%d", i), "policy blocked")
		if err != nil {
			t.Fatalf("buffer denial %d: %v", i, err)
		}
	}

	// First claim should return all 3 denials
	result, err := alertStore.ClaimFlushableDenials(ctx, 0)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if len(result["bot@example.com"]) != 3 {
		t.Fatalf("first claim: expected 3 denials, got %d", len(result["bot@example.com"]))
	}

	// Second claim should return empty — rows were atomically deleted
	result, err = alertStore.ClaimFlushableDenials(ctx, 0)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("second claim: expected empty map, got %d bots with denials", len(result))
	}
}

func TestDenialAlert_MultipleURLsBatched(t *testing.T) {
	if testPool == nil {
		t.Skip("no test database")
	}
	truncateTables(t)
	_, alertStore, alertService := newNotificationAPI(t)

	userStore := NewPGUserStore(testPool)
	mgrRole := "manager"
	userStore.CreateUser(CreateUserRequest{ID: "manager@example.com", Role: &mgrRole})
	userStore.CreateUser(CreateUserRequest{ID: "bot@example.com"})
	userStore.AssignManager("bot@example.com", "manager@example.com")

	ch := &alerting.NotificationChannel{
		OwnerID:     "manager@example.com",
		BotID:       "bot@example.com",
		ChannelType: "slack",
		Destination: "#test",
		Enabled:     true,
	}
	alertStore.CreateChannel(context.Background(), ch)

	mock := &mockSender{}
	alertService.RegisterSender("slack", mock)

	dispatcher := notifications.NewDispatcher()
	dispatcher.RegisterChannel(alertService)

	dispatcher.Broadcast(notifications.Event{
		Type: notifications.EventAuditEntry,
		Data: &types.AuditEntry{
			UserID: "bot@example.com", Method: "POST",
			URL: "https://api.github.com/repos/org/repo", Decision: "denied",
		},
	})
	dispatcher.Broadcast(notifications.Event{
		Type: notifications.EventAuditEntry,
		Data: &types.AuditEntry{
			UserID: "bot@example.com", Method: "POST",
			URL: "https://api.stripe.com/v1/charges", Decision: "denied",
		},
	})

	alertService.FlushNow()

	msgs := mock.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 notification (batched), got %d", len(msgs))
	}
	if len(msgs[0].Denials) != 2 {
		t.Errorf("expected 2 denials in batch, got %d", len(msgs[0].Denials))
	}
}
