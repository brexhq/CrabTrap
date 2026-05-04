package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brexhq/CrabTrap/internal/db"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// ---- Summary / Detail types ----

type UserSummary struct {
	ID           string    `json:"id"`
	Role         string    `json:"role"`
	IsAdmin      bool      `json:"is_admin"`
	LLMPolicyID  string    `json:"llm_policy_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	ChannelCount int       `json:"channel_count"`
}

type UserDetail struct {
	ID          string            `json:"id"`
	Role        string            `json:"role"`
	IsAdmin     bool              `json:"is_admin"`
	LLMPolicyID string            `json:"llm_policy_id,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Channels    []UserChannelInfo `json:"channels"`
}

type UserChannelInfo struct {
	ID               string `json:"id"`
	ChannelType      string `json:"channel_type"`
	WebToken         string `json:"web_token,omitempty"`
	GatewayAuthToken string `json:"gateway_auth_token,omitempty"`
}

// ---- Request types ----

type CreateUserRequest struct {
	ID               string  `json:"id"`
	IsAdmin          bool    `json:"is_admin"`
	Role             *string `json:"role,omitempty"`
	WebToken         string  `json:"web_token,omitempty"`
	GatewayAuthToken string  `json:"gateway_auth_token,omitempty"`
}

type UpdateUserRequest struct {
	IsAdmin          *bool   `json:"is_admin"`
	Role             *string `json:"role"`
	LLMPolicyID      *string `json:"llm_policy_id"`
	WebToken         *string `json:"web_token"`
	GatewayAuthToken *string `json:"gateway_auth_token"`
}

// ValidRoles is the set of accepted user role values.
var ValidRoles = map[string]bool{"admin": true, "manager": true, "user": true}

// resolveRole returns the effective role from a CreateUserRequest. If Role is
// explicitly set, it takes precedence; otherwise IsAdmin is used for backward
// compatibility.
func resolveRole(role *string, isAdmin bool) string {
	if role != nil && ValidRoles[*role] {
		return *role
	}
	if isAdmin {
		return "admin"
	}
	return "user"
}

// roleIsAdmin derives the legacy is_admin flag from the role column.
func roleIsAdmin(role string) bool {
	return role == "admin"
}

// ---- Interface ----

type UserStore interface {
	ListUsers() ([]UserSummary, error)
	GetUser(id string) (*UserDetail, error)
	CreateUser(req CreateUserRequest) (*UserDetail, error)
	UpdateUser(id string, req UpdateUserRequest) (*UserDetail, error)
	DeleteUser(id string) error
}

// ---- PGUserStore ----

type PGUserStore struct {
	pool *pgxpool.Pool
}

func NewPGUserStore(pool *pgxpool.Pool) *PGUserStore {
	return &PGUserStore{pool: pool}
}

func (s *PGUserStore) ListUsers() ([]UserSummary, error) {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.role, COALESCE(u.llm_policy_id, ''), u.created_at,
		       COUNT(DISTINCT uc.id) AS channel_count
		FROM users u
		LEFT JOIN user_channels uc ON uc.user_id = u.id
		GROUP BY u.id, u.role, u.llm_policy_id, u.created_at
		ORDER BY u.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []UserSummary{}
	for rows.Next() {
		var u UserSummary
		if err := rows.Scan(&u.ID, &u.Role, &u.LLMPolicyID, &u.CreatedAt,
			&u.ChannelCount); err != nil {
			return nil, err
		}
		u.IsAdmin = roleIsAdmin(u.Role)
		result = append(result, u)
	}
	return result, nil
}

func (s *PGUserStore) GetUser(id string) (*UserDetail, error) {
	ctx := context.Background()
	var u UserDetail
	err := s.pool.QueryRow(ctx, `
		SELECT id, role, COALESCE(llm_policy_id, ''), created_at, updated_at
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Role, &u.LLMPolicyID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	u.IsAdmin = roleIsAdmin(u.Role)

	// Fetch channels
	chanRows, err := s.pool.Query(ctx, `
		SELECT id, channel_type, payload FROM user_channels WHERE user_id = $1
	`, id)
	if err != nil {
		return nil, err
	}
	u.Channels = []UserChannelInfo{}
	for chanRows.Next() {
		var ch UserChannelInfo
		var payload []byte
		if err := chanRows.Scan(&ch.ID, &ch.ChannelType, &payload); err != nil {
			chanRows.Close()
			return nil, err
		}
		var p map[string]string
		if err := json.Unmarshal(payload, &p); err == nil {
			ch.WebToken = p["web_token"]
			ch.GatewayAuthToken = p["gateway_auth_token"]
		}
		u.Channels = append(u.Channels, ch)
	}
	chanRows.Close()

	return &u, nil
}

func (s *PGUserStore) CreateUser(req CreateUserRequest) (*UserDetail, error) {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	role := resolveRole(req.Role, req.IsAdmin)
	_, err = tx.Exec(ctx, `
		INSERT INTO users(id, is_admin, role) VALUES($1, $2, $3)
	`, req.ID, roleIsAdmin(role), role)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	if req.WebToken != "" {
		chanID := db.NewID("chan")
		payload, _ := json.Marshal(map[string]string{"web_token": req.WebToken})
		if _, err = tx.Exec(ctx, `
			INSERT INTO user_channels(id, user_id, channel_type, payload)
			VALUES($1, $2, 'web', $3)
		`, chanID, req.ID, payload); err != nil {
			return nil, fmt.Errorf("create web channel: %w", err)
		}
	}

	// Always provision a gateway_auth token — generate one if not explicitly supplied.
	gatToken := req.GatewayAuthToken
	if gatToken == "" {
		gatToken = db.NewGatewayAuthToken()
	}
	gatChanID := db.NewID("chan")
	gatPayload, _ := json.Marshal(map[string]string{"gateway_auth_token": gatToken})
	if _, err = tx.Exec(ctx, `
		INSERT INTO user_channels(id, user_id, channel_type, payload)
		VALUES($1, $2, 'gateway_auth', $3)
	`, gatChanID, req.ID, gatPayload); err != nil {
		return nil, fmt.Errorf("create gateway_auth channel: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetUser(req.ID)
}

func (s *PGUserStore) UpdateUser(id string, req UpdateUserRequest) (*UserDetail, error) {
	ctx := context.Background()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Build dynamic UPDATE for users table
	if req.Role != nil || req.IsAdmin != nil || req.LLMPolicyID != nil {
		setClauses := []string{"updated_at = NOW()"}
		args := []interface{}{}
		idx := 1
		if req.Role != nil && ValidRoles[*req.Role] {
			setClauses = append(setClauses, fmt.Sprintf("role = $%d", idx))
			args = append(args, *req.Role)
			idx++
			setClauses = append(setClauses, fmt.Sprintf("is_admin = $%d", idx))
			args = append(args, roleIsAdmin(*req.Role))
			idx++
		} else if req.IsAdmin != nil {
			setClauses = append(setClauses, fmt.Sprintf("is_admin = $%d", idx))
			args = append(args, *req.IsAdmin)
			idx++
			setClauses = append(setClauses, fmt.Sprintf("role = $%d", idx))
			args = append(args, resolveRole(nil, *req.IsAdmin))
			idx++
		}
		if req.LLMPolicyID != nil {
			if *req.LLMPolicyID == "" {
				setClauses = append(setClauses, "llm_policy_id = NULL")
			} else {
				setClauses = append(setClauses, fmt.Sprintf("llm_policy_id = $%d", idx))
				args = append(args, *req.LLMPolicyID)
				idx++
			}
		}
		args = append(args, id)
		q := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setClauses, ", "), idx)
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			return nil, fmt.Errorf("update user: %w", err)
		}
	}

	// Upsert/delete web channel
	if req.WebToken != nil {
		if *req.WebToken == "" {
			if _, err := tx.Exec(ctx, `DELETE FROM user_channels WHERE user_id = $1 AND channel_type = 'web'`, id); err != nil {
				return nil, fmt.Errorf("delete web channel: %w", err)
			}
		} else {
			chanID := db.NewID("chan")
			payload, _ := json.Marshal(map[string]string{"web_token": *req.WebToken})
			if _, err = tx.Exec(ctx, `
				INSERT INTO user_channels(id, user_id, channel_type, payload)
				VALUES($1, $2, 'web', $3)
				ON CONFLICT (user_id, channel_type) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()
			`, chanID, id, payload); err != nil {
				return nil, fmt.Errorf("upsert web channel: %w", err)
			}
		}
	}

	// Upsert/delete gateway_auth channel
	if req.GatewayAuthToken != nil {
		if *req.GatewayAuthToken == "" {
			if _, err := tx.Exec(ctx, `DELETE FROM user_channels WHERE user_id = $1 AND channel_type = 'gateway_auth'`, id); err != nil {
				return nil, fmt.Errorf("delete gateway_auth channel: %w", err)
			}
		} else {
			chanID := db.NewID("chan")
			payload, _ := json.Marshal(map[string]string{"gateway_auth_token": *req.GatewayAuthToken})
			if _, err = tx.Exec(ctx, `
				INSERT INTO user_channels(id, user_id, channel_type, payload)
				VALUES($1, $2, 'gateway_auth', $3)
				ON CONFLICT (user_id, channel_type) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()
			`, chanID, id, payload); err != nil {
				return nil, fmt.Errorf("upsert gateway_auth channel: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetUser(id)
}

func (s *PGUserStore) DeleteUser(id string) error {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("user not found")
	}
	return nil
}

// GetUserByWebToken looks up the gateway user ID and role for a given web token.
// During the transition period where is_admin and role may be out of sync (e.g.
// old code created an admin after the migration), we read both and prefer role
// but fall back to is_admin if role is still the default 'user'.
func (s *PGUserStore) GetUserByWebToken(token string) (string, string, bool) {
	if token == "" {
		return "", "", false
	}
	ctx := context.Background()
	var userID string
	var role string
	var isAdmin bool
	err := s.pool.QueryRow(ctx, `
		SELECT uc.user_id, u.role, u.is_admin
		FROM user_channels uc
		JOIN users u ON u.id = uc.user_id
		WHERE uc.channel_type = 'web' AND uc.payload->>'web_token' = $1
	`, token).Scan(&userID, &role, &isAdmin)
	if err != nil {
		return "", "", false
	}
	if role == "user" && isAdmin {
		role = "admin"
	}
	return userID, role, true
}

// GetUserByGatewayAuthToken looks up the gateway user ID for a given gateway auth token.
func (s *PGUserStore) GetUserByGatewayAuthToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	ctx := context.Background()
	var userID string
	err := s.pool.QueryRow(ctx, `
		SELECT uc.user_id
		FROM user_channels uc
		WHERE uc.channel_type = 'gateway_auth' AND uc.payload->>'gateway_auth_token' = $1
	`, token).Scan(&userID)
	if err != nil {
		return "", false
	}
	return userID, true
}

// GetLLMPolicyForUser returns the LLM policy linked to the given user, or nil if none is set.
func (s *PGUserStore) GetLLMPolicyForUser(userID string) *types.LLMPolicy {
	ctx := context.Background()
	var p types.LLMPolicy
	var forkedFrom *string
	err := s.pool.QueryRow(ctx, `
		SELECT lp.id, lp.name, lp.prompt, lp.provider, lp.model, lp.forked_from, lp.static_rules, lp.created_at
		FROM users u
		JOIN llm_policies lp ON lp.id = u.llm_policy_id
		WHERE u.id = $1 AND lp.deleted_at IS NULL
	`, userID).Scan(&p.ID, &p.Name, &p.Prompt, &p.Provider, &p.Model, &forkedFrom, &p.StaticRules, &p.CreatedAt)
	if err != nil {
		return nil
	}
	if forkedFrom != nil {
		p.ForkedFrom = *forkedFrom
	}
	return &p
}
