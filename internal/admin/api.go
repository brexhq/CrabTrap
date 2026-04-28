package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brexhq/CrabTrap/internal/approval"
	"github.com/brexhq/CrabTrap/internal/eval"
	"github.com/brexhq/CrabTrap/internal/judge"
	"github.com/brexhq/CrabTrap/internal/llmpolicy"
	"github.com/brexhq/CrabTrap/internal/notifications"
	"github.com/brexhq/CrabTrap/internal/builder"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// WebTokenValidator validates web UI tokens and returns the associated user ID and admin flag.
type WebTokenValidator interface {
	GetUserByWebToken(token string) (userID string, isAdmin bool, ok bool)
}

// UserResolver resolves user identity from various token types.
// Extends WebTokenValidator with gateway auth token lookup and per-user LLM policy resolution.
// Implemented by PGUserStore.
type UserResolver interface {
	WebTokenValidator
	GetUserByGatewayAuthToken(token string) (userID string, ok bool)
	GetLLMPolicyForUser(userID string) *types.LLMPolicy
}

// API provides admin endpoints for the gateway
type API struct {
	reader         AuditReaderIface
	dispatcher     *notifications.Dispatcher
	sseChannel     *notifications.SSEChannel
	tokenValidator WebTokenValidator    // may be nil
	userStore      UserStore            // may be nil
	policyStore    llmpolicy.Store      // may be nil
	evalStore      eval.Store           // may be nil
	evalJudge      *judge.LLMJudge      // may be nil — used only for eval background runs
	agent          *builder.PolicyAgent  // may be nil — used by agent endpoint
	serverCtx      context.Context      // cancelled on server shutdown; used for background work
	secureCookie   bool                 // when true, auth cookies are set with the Secure flag

	runCancelsMu sync.Mutex
	runCancels   map[string]context.CancelCauseFunc // keyed by run ID; cleaned up on completion
}

// NewAPI creates a new admin API
func NewAPI(reader AuditReaderIface, dispatcher *notifications.Dispatcher, sseChannel *notifications.SSEChannel, tokenValidator WebTokenValidator, userStore UserStore) *API {
	return &API{
		reader:         reader,
		dispatcher:     dispatcher,
		sseChannel:     sseChannel,
		tokenValidator: tokenValidator,
		userStore:      userStore,
		runCancels:     make(map[string]context.CancelCauseFunc),
	}
}

// SetLLMPolicyStore configures the policy store used by the policy endpoints.
func (a *API) SetLLMPolicyStore(s llmpolicy.Store) {
	a.policyStore = s
}

// SetEvalRunner configures the eval store and judge used by the eval endpoints.
func (a *API) SetEvalRunner(store eval.Store, j *judge.LLMJudge) {
	a.evalStore = store
	a.evalJudge = j
}

// SetAgent configures the PolicyAgent used by POST /{id}/agent.
func (a *API) SetAgent(ag *builder.PolicyAgent) {
	a.agent = ag
}

// SetServerContext sets a context that will be cancelled when the server shuts
// down. Background eval goroutines inherit this context so they can be
// interrupted cleanly during shutdown.
func (a *API) SetServerContext(ctx context.Context) {
	a.serverCtx = ctx
}

// SetSecureCookie enables the Secure flag on auth cookies. Enable this when the
// admin API is served over TLS or behind a TLS-terminating reverse proxy.
func (a *API) SetSecureCookie(secure bool) {
	a.secureCookie = secure
}

// authCookieName is the name of the HttpOnly cookie used for session auth.
const authCookieName = "token"

// newAuthCookie creates an auth cookie with all security flags applied.
func (a *API) newAuthCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     authCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteStrictMode,
	}
}

// handleLogin validates a token and sets an HttpOnly auth cookie.
// POST /admin/login  body: {"token":"..."}
func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.tokenValidator == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	limitBody(w, r, maxBodySize)
	var body struct {
		Token string `json:"token"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Token == "" {
		http.Error(w, "token is required", http.StatusBadRequest)
		return
	}

	userID, isAdmin, ok := a.tokenValidator.GetUserByWebToken(body.Token)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Set HttpOnly cookie (7-day expiry).
	http.SetCookie(w, a.newAuthCookie(body.Token, 7*24*60*60))
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":  userID,
		"is_admin": isAdmin,
	})
}

// handleLogout clears the auth cookie.
// POST /admin/logout
func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Set cookie with MaxAge -1 to delete it.
	http.SetCookie(w, a.newAuthCookie("", -1))
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RegisterRoutes registers all admin routes
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	// Auth endpoints (login sets HttpOnly cookie, logout clears it)
	mux.HandleFunc("/admin/login", a.handleLogin)
	mux.HandleFunc("/admin/logout", a.handleLogout)

	// Audit endpoints
	mux.HandleFunc("/admin/audit", a.handleAuditLog)

	// SSE endpoint
	mux.HandleFunc("/admin/events", a.handleSSE)

	// Identity endpoint
	mux.HandleFunc("/admin/me", a.handleMe)

	// Health endpoint (shows pending count)
	mux.HandleFunc("/admin/health", a.handleHealth)

	// User management endpoints
	mux.HandleFunc("/admin/users", a.handleUsers)
	mux.HandleFunc("/admin/users/", a.handleUserAction)

	// LLM policy endpoints
	// GET/POST /admin/llm-policies
	// GET/PUT/DELETE /admin/llm-policies/{id}
	// POST /admin/llm-policies/{id}/publish
	// POST /admin/llm-policies/{id}/fork
	// POST /admin/llm-policies/{id}/agent  (SSE agent loop)
	// POST /admin/llm-policies/{id}/chat   (alias for agent)
	// POST /admin/llm-policies/{id}/chat   (deprecated alias for agent)
	mux.HandleFunc("/admin/llm-policies", a.handleLLMPolicies)
	mux.HandleFunc("/admin/llm-policies/", a.handleLLMPolicyAction)

	// Eval endpoints
	mux.HandleFunc("/admin/evals", a.handleEvals)
	mux.HandleFunc("/admin/evals/", a.handleEvalAction)

	// Audit label endpoints (sub-routes under /admin/audit/)
	mux.HandleFunc("/admin/audit/", a.handleAuditLabelAction)

	// LLM response lookup
	mux.HandleFunc("/admin/llm-responses/", a.handleLLMResponse)
}

// extractWebToken extracts the bearer token from the request.
// Priority: Authorization: Bearer header > token cookie.
// Tokens are NOT accepted via URL query parameters to avoid leaking
// credentials in server logs, browser history, and Referer headers.
func extractWebToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if cookie, err := r.Cookie("token"); err == nil {
		return cookie.Value
	}
	return ""
}

// requireAdmin writes 401/403 and returns false if the caller is not an authenticated admin.
func (a *API) requireAdmin(w http.ResponseWriter, r *http.Request) (userID string, ok bool) {
	token := extractWebToken(r)
	if token == "" || a.tokenValidator == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}
	uid, isAdmin, found := a.tokenValidator.GetUserByWebToken(token)
	if !found {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}
	if !isAdmin {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return "", false
	}
	return uid, true
}

// handleMe returns the authenticated user's identity and admin flag.
func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := extractWebToken(r)
	if token == "" || a.tokenValidator == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, isAdmin, ok := a.tokenValidator.GetUserByWebToken(token)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":  userID,
		"is_admin": isAdmin,
	})
}

// handleAuditLog returns audit entries with optional filters
func (a *API) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	filter := AuditFilter{
		UserID:     query.Get("user_id"),
		Decision:   query.Get("decision"),
		ApprovedBy: query.Get("approved_by"),
		Channel:    query.Get("channel"),
		Method:     query.Get("method"),
		PolicyID:   query.Get("policy_id"),
	}

	// Parse cache_hit filter
	if cacheHitStr := query.Get("cache_hit"); cacheHitStr != "" {
		cacheHit := cacheHitStr == "true"
		filter.CacheHit = &cacheHit
	}

	// Parse time range. Use RFC3339Nano so that the millisecond precision
	// produced by JavaScript's toISOString() (e.g. "…T21:30:00.000Z") is
	// accepted — time.RFC3339 rejects the fractional-seconds component.
	if startStr := query.Get("start_time"); startStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, startStr); err == nil {
			filter.StartTime = t
		}
	}
	if endStr := query.Get("end_time"); endStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, endStr); err == nil {
			filter.EndTime = t
		}
	}

	// Parse pagination
	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	} else {
		filter.Limit = 100 // Default limit
	}

	if offsetStr := query.Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}

	entries := a.reader.Query(filter)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"offset":  filter.Offset,
		"limit":   filter.Limit,
	})
}

// handleSSE handles Server-Sent Events connections. Requires admin authentication.
func (a *API) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.sseChannel.ServeHTTPForUser(w, r, userID)
}

// handleHealth returns basic health information
func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
	})
}

// handleUsers handles GET /admin/users (list) and POST /admin/users (create).
func (a *API) handleUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.userStore == nil {
		http.Error(w, "User store not available", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := a.userStore.ListUsers()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to list users", err)
			return
		}
		respondJSON(w, http.StatusOK, users)
	case http.MethodPost:
		limitBody(w, r, maxBodySize)
		var req CreateUserRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if req.ID == "" {
			http.Error(w, "id (email) is required", http.StatusBadRequest)
			return
		}
		user, err := a.userStore.CreateUser(req)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to create user", err)
			return
		}
		respondJSON(w, http.StatusCreated, user)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUserAction routes /admin/users/{email}.
func (a *API) handleUserAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.userStore == nil {
		http.Error(w, "User store not available", http.StatusServiceUnavailable)
		return
	}

	const prefix = "/admin/users/"
	// Use RawPath when available so we unescape exactly once.
	rawPath := r.URL.RawPath
	if rawPath == "" {
		rawPath = r.URL.Path
	}
	remaining := rawPath[len(prefix):]
	if remaining == "" {
		http.NotFound(w, r)
		return
	}

	email, err := url.PathUnescape(remaining)
	if err != nil || email == "" {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		user, err := a.userStore.GetUser(email)
		if err != nil {
			respondError(w, http.StatusNotFound, "user not found", err)
			return
		}
		respondJSON(w, http.StatusOK, user)
	case http.MethodPut:
		limitBody(w, r, maxBodySize)
		var req UpdateUserRequest
		if !decodeBody(w, r, &req) {
			return
		}
		if req.LLMPolicyID != nil && *req.LLMPolicyID != "" && a.policyStore != nil {
			policy, err := a.policyStore.Get(*req.LLMPolicyID)
			if err != nil {
				http.Error(w, "policy not found: "+*req.LLMPolicyID, http.StatusBadRequest)
				return
			}
			if policy.Status == "draft" {
				http.Error(w, "cannot assign a draft policy to a user; publish it first", http.StatusBadRequest)
				return
			}
		}
		user, err := a.userStore.UpdateUser(email, req)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to update user", err)
			return
		}
		respondJSON(w, http.StatusOK, user)
	case http.MethodDelete:
		if err := a.userStore.DeleteUser(email); err != nil {
			respondError(w, http.StatusNotFound, "user not found", err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLLMPolicies handles GET (list) and POST (create) for /admin/llm-policies.
func (a *API) handleLLMPolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.policyStore == nil {
		http.Error(w, "LLM policy store not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 50
		offset := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		policies, err := a.policyStore.List(limit, offset)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to list policies", err)
			return
		}
		if policies == nil {
			policies = []*types.LLMPolicy{}
		}
		respondJSON(w, http.StatusOK, policies)

	case http.MethodPost:
		limitBody(w, r, maxBodySize)
		var body struct {
			Name        string             `json:"name"`
			Prompt      string             `json:"prompt"`
			Provider    string             `json:"provider"`
			Model       string             `json:"model"`
			Status      string             `json:"status"`
			StaticRules []types.StaticRule `json:"static_rules"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if err := approval.ValidateStaticRules(body.StaticRules); err != nil {
			http.Error(w, "invalid static_rules: "+err.Error(), http.StatusBadRequest)
			return
		}
		policy, err := a.policyStore.Create(body.Name, body.Prompt, body.Provider, body.Model, "", body.Status, body.StaticRules)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to create policy", err)
			return
		}
		respondJSON(w, http.StatusCreated, policy)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLLMPolicyAction handles GET /admin/llm-policies/{id} and
// POST /admin/llm-policies/{id}/fork.
func (a *API) handleLLMPolicyAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.policyStore == nil {
		http.Error(w, "LLM policy store not configured", http.StatusServiceUnavailable)
		return
	}

	path := r.URL.Path
	var id, action string
	if len(path) > len("/admin/llm-policies/") {
		remaining := path[len("/admin/llm-policies/"):]
		for i, c := range remaining {
			if c == '/' {
				id = remaining[:i]
				if i+1 < len(remaining) {
					action = remaining[i+1:]
				}
				break
			}
		}
		if id == "" {
			id = remaining
		}
	}
	if id == "" {
		http.Error(w, "Missing policy ID", http.StatusBadRequest)
		return
	}

	switch {
	case r.Method == http.MethodGet && action == "":
		policy, err := a.policyStore.Get(id)
		if err != nil {
			respondError(w, http.StatusNotFound, "policy not found", err)
			return
		}
		respondJSON(w, http.StatusOK, policy)

	case r.Method == http.MethodGet && action == "metadata":
		meta, err := a.policyStore.GetMetadata(id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to get policy metadata", err)
			return
		}
		if meta == nil {
			respondJSON(w, http.StatusOK, &types.PolicyMetadata{})
			return
		}
		respondJSON(w, http.StatusOK, meta)

	case r.Method == http.MethodGet && action == "stats":
		stats, err := a.reader.GetPolicyStats(id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to get policy stats", err)
			return
		}
		respondJSON(w, http.StatusOK, stats)

	case r.Method == http.MethodPut && action == "":
		// Update a draft policy's editable fields.
		limitBody(w, r, maxBodySize)
		var body struct {
			Name        string             `json:"name"`
			Prompt      string             `json:"prompt"`
			Provider    string             `json:"provider"`
			Model       string             `json:"model"`
			StaticRules []types.StaticRule `json:"static_rules"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if err := approval.ValidateStaticRules(body.StaticRules); err != nil {
			http.Error(w, "invalid static_rules: "+err.Error(), http.StatusBadRequest)
			return
		}
		policy, err := a.policyStore.UpdateDraft(id, body.Name, body.Prompt, body.Provider, body.Model, body.StaticRules)
		if err != nil {
			if errors.Is(err, llmpolicy.ErrPolicyNotDraft) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			respondError(w, http.StatusInternalServerError, "failed to update policy", err)
			return
		}
		respondJSON(w, http.StatusOK, policy)

	case r.Method == http.MethodPost && action == "publish":
		policy, err := a.policyStore.Publish(id)
		if err != nil {
			if errors.Is(err, llmpolicy.ErrPolicyNotDraft) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			respondError(w, http.StatusNotFound, "policy not found", err)
			return
		}
		slog.Info("Admin API: published llm_policy", "policy_id", id)
		respondJSON(w, http.StatusOK, policy)

	case r.Method == http.MethodPost && action == "fork":
		limitBody(w, r, maxBodySize)
		parent, err := a.policyStore.Get(id)
		if err != nil {
			respondError(w, http.StatusNotFound, "policy not found", err)
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		body.Name = parent.Name + " (draft)"
		if !decodeBody(w, r, &body) {
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		// Fork always creates a draft so the user can edit before publishing.
		policy, err := a.policyStore.Create(body.Name, parent.Prompt, parent.Provider, parent.Model, id, "draft", parent.StaticRules)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to fork policy", err)
			return
		}
		slog.Info("Admin API: forked llm_policy", "parent_id", id, "new_id", policy.ID)
		respondJSON(w, http.StatusCreated, policy)

	case (r.Method == http.MethodPost && action == "agent") ||
		(r.Method == http.MethodPost && action == "chat"):
		// "chat" is a deprecated alias kept for backward compatibility.
		if a.agent == nil {
			http.Error(w, "Policy agent not configured", http.StatusServiceUnavailable)
			return
		}
		policy, err := a.policyStore.Get(id)
		if err != nil {
			respondError(w, http.StatusNotFound, "policy not found", err)
			return
		}
		if policy.Status != "draft" {
			http.Error(w, "agent editing is only available for draft policies", http.StatusConflict)
			return
		}
		limitBody(w, r, maxBodySize)
		var body struct {
			Message string                `json:"message"`
			History []builder.ChatMessage `json:"history"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.Message == "" {
			http.Error(w, "message is required", http.StatusBadRequest)
			return
		}

		var summaries []types.PolicyEndpointSummary
		if meta, err := a.policyStore.GetMetadata(id); err == nil && meta != nil {
			summaries = meta.EndpointSummaries
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		agentCtx := r.Context()
		if a.serverCtx != nil {
			var cancel context.CancelFunc
			agentCtx, cancel = context.WithCancel(agentCtx)
			defer cancel()
			go func() {
				select {
				case <-a.serverCtx.Done():
					cancel()
				case <-agentCtx.Done():
				}
			}()
		}

		result, err := a.agent.Run(
			agentCtx,
			policy.Name, policy.Prompt, policy.StaticRules, summaries,
			body.History, body.Message,
			func(eventType string, data interface{}) {
				writeSEEvent(w, eventType, data)
				if eventType == "summaries_updated" && a.policyStore != nil {
					if s, ok := data.([]types.PolicyEndpointSummary); ok {
						a.policyStore.SetEndpointSummaries(id, s) //nolint:errcheck
					}
				}
			},
		)
		if err != nil {
			writeSEEvent(w, "error", map[string]string{"message": err.Error()})
			return
		}

		if a.policyStore != nil {
			// Persist policy/name changes.
			name := policy.Name
			if result.NewName != "" {
				name = result.NewName
			}
			if result.PolicyUpdated || result.NewName != "" {
				a.policyStore.UpdateDraft(id, name, result.PolicyPrompt, policy.Provider, policy.Model, result.StaticRules) //nolint:errcheck
			}
			// Always persist the final summaries state (covers analyze_traffic, remove_endpoints,
			// and the case where all endpoints were removed — empty slice must be saved too).
			a.policyStore.SetEndpointSummaries(id, result.NewSummaries) //nolint:errcheck

			// Persist the full turn (user message + tool calls/results + final reply).
			if len(result.NewMessages) > 0 {
				a.policyStore.SetChatHistory(id, append(body.History, result.NewMessages...)) //nolint:errcheck
			}
		}

		writeSEEvent(w, "result", map[string]interface{}{
			"message":            result.Message,
			"policy_updated":     result.PolicyUpdated,
			"policy_prompt":      result.PolicyPrompt,
			"static_rules":       result.StaticRules,
			"endpoint_summaries": result.NewSummaries,
			"new_name":           result.NewName,
			"new_messages":       result.NewMessages,
		})
		writeSEEvent(w, "done", map[string]string{})

	case r.Method == http.MethodDelete && action == "":
		if err := a.policyStore.Delete(id); err != nil {
			if errors.Is(err, llmpolicy.ErrPolicyHasAssignedUsers) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			if errors.Is(err, llmpolicy.ErrPolicyNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			respondError(w, http.StatusInternalServerError, "failed to delete policy", err)
			return
		}
		slog.Info("Admin API: soft-deleted llm_policy", "policy_id", id)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEvals handles GET /admin/evals (list) and POST /admin/evals (create).
//
// POST body: {"policy_id":"llmpol_xxx","filter":{"limit":100,"decision":"approved",...}}
func (a *API) handleEvals(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.evalStore == nil {
		http.Error(w, "Eval store not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		policyID := r.URL.Query().Get("policy_id")
		limit := 50
		offset := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		runs, err := a.evalStore.ListRuns(policyID, limit, offset)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to list eval runs", err)
			return
		}
		respondJSON(w, http.StatusOK, runs)

	case http.MethodPost:
		limitBody(w, r, maxBodySize)
		var body struct {
			PolicyID string `json:"policy_id"`
			Filter   struct {
				Limit     int    `json:"limit"`
				Decision  string `json:"decision"`
				UserID    string `json:"user_id"`
				StartTime string `json:"start_time"`
				EndTime   string `json:"end_time"`
			} `json:"filter"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.PolicyID == "" {
			http.Error(w, "policy_id is required", http.StatusBadRequest)
			return
		}
		if a.policyStore == nil {
			http.Error(w, "LLM policy store not configured", http.StatusServiceUnavailable)
			return
		}
		policy, err := a.policyStore.Get(body.PolicyID)
		if err != nil {
			http.Error(w, "policy not found: "+body.PolicyID, http.StatusNotFound)
			return
		}
		if a.evalJudge == nil {
			http.Error(w, "LLM judge not configured", http.StatusServiceUnavailable)
			return
		}
		filter := AuditFilter{
			Decision:        body.Filter.Decision,
			UserID:          body.Filter.UserID,
			Limit:           body.Filter.Limit,
			ExcludeChannels:    []string{"auto"},
		}
		if body.Filter.StartTime != "" {
			if t, err := time.Parse(time.RFC3339Nano, body.Filter.StartTime); err == nil {
				filter.StartTime = t
			}
		}
		if body.Filter.EndTime != "" {
			if t, err := time.Parse(time.RFC3339Nano, body.Filter.EndTime); err == nil {
				filter.EndTime = t
			}
		}
		run, err := a.evalStore.CreateRun(body.PolicyID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to create eval run", err)
			return
		}
		baseCtx := a.serverCtx
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		runCtx, runCancel := context.WithCancelCause(baseCtx)
		a.runCancelsMu.Lock()
		a.runCancels[run.ID] = runCancel
		a.runCancelsMu.Unlock()

		if n, countErr := a.reader.Count(runCtx, filter); countErr == nil {
			total := n
			if filter.Limit > 0 && n > filter.Limit {
				total = filter.Limit
			}
			a.evalStore.SetTotalEntries(run.ID, total) //nolint:errcheck
			run.TotalEntries = total
		}
		entryCh := make(chan types.AuditEntry, 100)
		go func() {
			defer close(entryCh)
			a.reader.QueryBatched(runCtx, filter, 500, func(batch []types.AuditEntry) error { //nolint:errcheck
				for _, e := range batch {
					select {
					case <-runCtx.Done():
						return runCtx.Err()
					case entryCh <- e:
					}
				}
				return nil
			}) //nolint:errcheck
		}()
		go func() {
			defer func() {
				runCancel(nil) // nil = normal completion; ErrUserCanceled set explicitly on cancel
				a.runCancelsMu.Lock()
				delete(a.runCancels, run.ID)
				a.runCancelsMu.Unlock()
			}()
			eval.RunEval(runCtx, a.evalJudge, entryCh, *policy, a.evalStore, run.ID)
		}()
		respondJSON(w, http.StatusCreated, run)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEvalAction handles GET /admin/evals/{id} and GET /admin/evals/{id}/results.
func (a *API) handleEvalAction(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if a.evalStore == nil {
		http.Error(w, "Eval store not configured", http.StatusServiceUnavailable)
		return
	}

	path := r.URL.Path
	var id, action string
	if len(path) > len("/admin/evals/") {
		remaining := path[len("/admin/evals/"):]
		for i, c := range remaining {
			if c == '/' {
				id = remaining[:i]
				if i+1 < len(remaining) {
					action = remaining[i+1:]
				}
				break
			}
		}
		if id == "" {
			id = remaining
		}
	}
	if id == "" {
		http.Error(w, "Missing eval run ID", http.StatusBadRequest)
		return
	}

	switch {
	case r.Method == http.MethodGet && action == "":
		run, err := a.evalStore.GetRun(id)
		if err != nil {
			respondError(w, http.StatusNotFound, "eval run not found", err)
			return
		}
		respondJSON(w, http.StatusOK, run)

	case r.Method == http.MethodPost && action == "cancel":
		a.runCancelsMu.Lock()
		cancel, ok := a.runCancels[id]
		a.runCancelsMu.Unlock()
		if !ok {
			http.Error(w, "run is not currently running", http.StatusConflict)
			return
		}
		cancel(eval.ErrUserCanceled)
		respondJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})

	case r.Method == http.MethodGet && action == "stats":
		stats, err := a.evalStore.GetRunStats(id)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to get eval run stats", err)
			return
		}
		respondJSON(w, http.StatusOK, stats)

	case r.Method == http.MethodGet && action == "results":
		limit := 100
		offset := 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		var resultFilter eval.ResultFilter
		if v := r.URL.Query().Get("approved_by"); v != "" {
			resultFilter.ApprovedBy = v
		}
		if v := r.URL.Query().Get("replay_decision"); v != "" {
			resultFilter.ReplayDecision = v
		}
		if v := r.URL.Query().Get("has_label"); v != "" {
			b := v == "true"
			resultFilter.HasLabel = &b
		}
		if v := r.URL.Query().Get("matched"); v != "" {
			b := v == "true"
			resultFilter.Matched = &b
		}
		if v := r.URL.Query().Get("url"); v != "" {
			resultFilter.URL = v
		}
		results, total, err := a.evalStore.ListResults(id, resultFilter, limit, offset)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "failed to list eval results", err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"results": results,
			"total":   total,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAuditLabelAction handles PUT and DELETE for /admin/audit/{id}/label.
func (a *API) handleAuditLabelAction(w http.ResponseWriter, r *http.Request) {
	userID, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	if a.evalStore == nil {
		http.Error(w, "Eval store not configured", http.StatusServiceUnavailable)
		return
	}

	// Accepted paths:
	//   GET /admin/audit/{id}
	//   PUT /admin/audit/{id}/label
	//   DELETE /admin/audit/{id}/label
	const prefix = "/admin/audit/"
	path := r.URL.Path
	if !strings.HasPrefix(path, prefix) {
		http.NotFound(w, r)
		return
	}
	rest := path[len(prefix):]
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	entryID := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	if len(parts) > 2 || (len(parts) == 2 && action != "label") {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if action != "" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entry, err := a.reader.GetEntry(entryID)
		if err != nil {
			respondError(w, http.StatusNotFound, "audit entry not found", err)
			return
		}
		respondJSON(w, http.StatusOK, entry)

	case http.MethodPut:
		limitBody(w, r, maxBodySize)
		var body struct {
			Decision string `json:"decision"`
			Note     string `json:"note"`
		}
		if !decodeBody(w, r, &body) {
			return
		}
		if body.Decision == "" {
			http.Error(w, "decision is required", http.StatusBadRequest)
			return
		}
		if err := a.evalStore.UpsertLabel(eval.AuditLabel{
			EntryID:   entryID,
			Decision:  body.Decision,
			Note:      body.Note,
			LabeledBy: userID,
		}); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to upsert label", err)
			return
		}
		lbl, err := a.evalStore.GetLabel(entryID)
		if err != nil || lbl == nil {
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		respondJSON(w, http.StatusOK, lbl)

	case http.MethodDelete:
		if err := a.evalStore.DeleteLabel(entryID); err != nil {
			respondError(w, http.StatusInternalServerError, "failed to delete label", err)
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleLLMResponse handles GET /admin/llm-responses/{id}.
func (a *API) handleLLMResponse(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.evalStore == nil {
		http.Error(w, "Eval store not configured", http.StatusServiceUnavailable)
		return
	}
	const prefix = "/admin/llm-responses/"
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if id == "" {
		http.Error(w, "Missing llm_response ID", http.StatusBadRequest)
		return
	}
	resp, err := a.evalStore.GetLLMResponse(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "LLM response not found", err)
		return
	}
	respondJSON(w, http.StatusOK, resp)
}


// respondError writes a generic publicMsg to the client and logs the detailed
// error server-side. This prevents raw database error strings (table names,
// constraints, SQL fragments) from leaking to callers.
func respondError(w http.ResponseWriter, statusCode int, publicMsg string, err error) {
	if err != nil {
		slog.Error("Admin API error", "message", publicMsg, "error", err)
	}
	http.Error(w, publicMsg, statusCode)
}

// limitBody wraps r.Body with http.MaxBytesReader to cap the request body at
// maxBytes. Passing the ResponseWriter allows Go to signal connection close
// when the limit is exceeded. Call at the top of any handler that decodes the
// request body.
func limitBody(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
}

// maxBodySize is the default request body size limit (1 MB).
const maxBodySize = 1 << 20

// decodeBody JSON-decodes the request body into dst, handling MaxBytesError
// (returns 413) and sanitising other decode errors so internal type names are
// not leaked to callers. Returns true on success; on failure it writes an
// error response and returns false.
func decodeBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		respondError(w, http.StatusBadRequest, "Invalid request body", err)
		return false
	}
	return true
}

// writeSEEvent writes a single SSE event and flushes the response.
func writeSEEvent(w http.ResponseWriter, event string, data interface{}) {
	payload, _ := json.Marshal(data)
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, payload)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// respondJSON writes a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("error encoding JSON response", "error", err)
	}
}
