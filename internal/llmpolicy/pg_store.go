package llmpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brexhq/CrabTrap/internal/db"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// Sentinel errors returned by Store operations.
var (
	ErrPolicyNotFound         = errors.New("llm_policy not found")
	ErrPolicyHasAssignedUsers = errors.New("policy is assigned to users; unassign them before deleting")
	ErrPolicyNotDraft         = errors.New("policy is not a draft; only drafts can be edited")
)

// Store manages LLM policy records.
type Store interface {
	Get(id string) (*types.LLMPolicy, error)
	List(limit, offset int) ([]*types.LLMPolicy, error)
	GetMetadata(id string) (*types.PolicyMetadata, error)
	UpsertMetadata(id string, metadata *types.PolicyMetadata) error
	Create(name, prompt, provider, model, forkedFrom, status string, staticRules []types.StaticRule) (*types.LLMPolicy, error)
	UpdateDraft(id, name, prompt, provider, model string, staticRules []types.StaticRule) (*types.LLMPolicy, error)
	Publish(id string) (*types.LLMPolicy, error)
	SetEndpointSummaries(id string, summaries []types.PolicyEndpointSummary) error
	SetChatHistory(id string, history []types.ChatMessage) error
	Delete(id string) error
}

// PGStore implements Store using PostgreSQL.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a PGStore backed by the given pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// scanPolicy reads one row from the standard policy SELECT (no metadata join).
func scanPolicy(row interface {
	Scan(dest ...any) error
}) (*types.LLMPolicy, error) {
	var p types.LLMPolicy
	var forkedFrom *string
	err := row.Scan(
		&p.ID, &p.Name, &p.Prompt, &p.Provider, &p.Model,
		&p.Status, &forkedFrom, &p.StaticRules,
		&p.CreatedAt, &p.DeletedAt,
	)
	if err != nil {
		return nil, err
	}
	if forkedFrom != nil {
		p.ForkedFrom = *forkedFrom
	}
	types.NormalizeStaticRules(p.StaticRules)
	return &p, nil
}

const selectCols = `id, name, prompt, provider, model, status, forked_from, static_rules, created_at, deleted_at`

// Get fetches a single policy by ID. Metadata is not included; call GetMetadata separately.
func (s *PGStore) Get(id string) (*types.LLMPolicy, error) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx,
		`SELECT `+selectCols+` FROM llm_policies WHERE id = $1`, id)
	p, err := scanPolicy(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("llm_policy not found: %s", id)
		}
		return nil, fmt.Errorf("Get llm_policy: %w", err)
	}
	return p, nil
}

// List returns non-deleted policies ordered by creation time descending.
// Metadata is not included; call GetMetadata separately if needed.
func (s *PGStore) List(limit, offset int) ([]*types.LLMPolicy, error) {
	if limit <= 0 {
		limit = 50
	}
	ctx := context.Background()
	rows, err := s.pool.Query(ctx,
		`SELECT `+selectCols+` FROM llm_policies WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, fmt.Errorf("List llm_policies: %w", err)
	}
	defer rows.Close()

	var policies []*types.LLMPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("List llm_policies scan: %w", err)
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// GetMetadata fetches the builder metadata for a policy from llm_policy_builder_metadata.
// Returns nil (not an error) if no metadata row exists yet.
func (s *PGStore) GetMetadata(id string) (*types.PolicyMetadata, error) {
	ctx := context.Background()
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT metadata FROM llm_policy_builder_metadata WHERE policy_id = $1`, id,
	).Scan(&raw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("GetMetadata: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var m types.PolicyMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("GetMetadata unmarshal: %w", err)
	}
	return &m, nil
}

// UpsertMetadata replaces (or creates) the full builder metadata row for a policy.
func (s *PGStore) UpsertMetadata(id string, metadata *types.PolicyMetadata) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("UpsertMetadata marshal: %w", err)
	}
	ctx := context.Background()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO llm_policy_builder_metadata (policy_id, metadata, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (policy_id) DO UPDATE
		SET metadata = $2, updated_at = NOW()
	`, id, b)
	return err
}

// Create inserts a new policy record.
// status should be "draft" or "published"; defaults to "published" if empty.
// Builder metadata is not created here — it is written lazily on first update.
func (s *PGStore) Create(name, prompt, provider, model, forkedFrom, status string, staticRules []types.StaticRule) (*types.LLMPolicy, error) {
	if status == "" {
		status = "published"
	}
	if staticRules == nil {
		staticRules = []types.StaticRule{}
	}
	types.NormalizeStaticRules(staticRules)
	var forkedFromPtr *string
	if forkedFrom != "" {
		forkedFromPtr = &forkedFrom
	}

	id := db.NewID("llmpol")
	ctx := context.Background()
	var createdAt time.Time
	err := s.pool.QueryRow(ctx, `
		INSERT INTO llm_policies(id, name, prompt, provider, model, status, forked_from, static_rules)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at
	`, id, name, prompt, provider, model, status, forkedFromPtr, staticRules).Scan(&createdAt)
	if err != nil {
		return nil, fmt.Errorf("Create llm_policy: %w", err)
	}
	p := &types.LLMPolicy{
		ID:          id,
		Name:        name,
		Prompt:      prompt,
		Provider:    provider,
		Model:       model,
		Status:      status,
		StaticRules: staticRules,
		CreatedAt:   createdAt,
	}
	if forkedFrom != "" {
		p.ForkedFrom = forkedFrom
	}
	return p, nil
}

// UpdateDraft updates a draft policy's editable fields.
// Returns ErrPolicyNotDraft if the policy is not in draft status.
func (s *PGStore) UpdateDraft(id, name, prompt, provider, model string, staticRules []types.StaticRule) (*types.LLMPolicy, error) {
	if staticRules == nil {
		staticRules = []types.StaticRule{}
	}
	types.NormalizeStaticRules(staticRules)
	ctx := context.Background()

	tag, err := s.pool.Exec(ctx, `
		UPDATE llm_policies
		SET name=$2, prompt=$3, provider=$4, model=$5, static_rules=$6
		WHERE id=$1 AND status='draft' AND deleted_at IS NULL
	`, id, name, prompt, provider, model, staticRules)
	if err != nil {
		return nil, fmt.Errorf("UpdateDraft: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrPolicyNotDraft
	}
	return s.Get(id)
}

// Publish transitions a draft policy to published status (one-way).
// Returns ErrPolicyNotDraft if already published or not found.
func (s *PGStore) Publish(id string) (*types.LLMPolicy, error) {
	ctx := context.Background()
	tag, err := s.pool.Exec(ctx, `
		UPDATE llm_policies SET status='published'
		WHERE id=$1 AND status='draft' AND deleted_at IS NULL
	`, id)
	if err != nil {
		return nil, fmt.Errorf("Publish: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrPolicyNotDraft
	}
	return s.Get(id)
}

// SetEndpointSummaries upserts endpoint_summaries in the builder metadata row,
// preserving all other metadata fields.
func (s *PGStore) SetEndpointSummaries(id string, summaries []types.PolicyEndpointSummary) error {
	if summaries == nil {
		summaries = []types.PolicyEndpointSummary{}
	}
	b, err := json.Marshal(summaries)
	if err != nil {
		return fmt.Errorf("SetEndpointSummaries marshal: %w", err)
	}
	ctx := context.Background()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO llm_policy_builder_metadata (policy_id, metadata, updated_at)
		VALUES ($1, jsonb_build_object('endpoint_summaries', $2::jsonb), NOW())
		ON CONFLICT (policy_id) DO UPDATE
		SET metadata   = jsonb_set(COALESCE(llm_policy_builder_metadata.metadata, '{}'::jsonb), '{endpoint_summaries}', $2::jsonb),
		    updated_at = NOW()
	`, id, b)
	return err
}

// SetChatHistory upserts chat_history in the builder metadata row,
// preserving all other metadata fields.
func (s *PGStore) SetChatHistory(id string, history []types.ChatMessage) error {
	if history == nil {
		history = []types.ChatMessage{}
	}
	b, err := json.Marshal(history)
	if err != nil {
		return fmt.Errorf("SetChatHistory marshal: %w", err)
	}
	ctx := context.Background()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO llm_policy_builder_metadata (policy_id, metadata, updated_at)
		VALUES ($1, jsonb_build_object('chat_history', $2::jsonb), NOW())
		ON CONFLICT (policy_id) DO UPDATE
		SET metadata   = jsonb_set(COALESCE(llm_policy_builder_metadata.metadata, '{}'::jsonb), '{chat_history}', $2::jsonb),
		    updated_at = NOW()
	`, id, b)
	return err
}

// Delete soft-deletes a policy. Returns an error if any users are currently
// assigned to it (to avoid leaving live traffic without a policy).
func (s *PGStore) Delete(id string) error {
	ctx := context.Background()

	tag, err := s.pool.Exec(ctx, `
		UPDATE llm_policies SET deleted_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM users WHERE llm_policy_id = $1)
	`, id)
	if err != nil {
		return fmt.Errorf("Delete llm_policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var hasUsers bool
		_ = s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE llm_policy_id = $1)`, id,
		).Scan(&hasUsers)
		if hasUsers {
			return ErrPolicyHasAssignedUsers
		}
		return ErrPolicyNotFound
	}
	return nil
}
