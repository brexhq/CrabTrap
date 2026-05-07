package alerting

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brexhq/CrabTrap/internal/db"
)

type NotificationChannel struct {
	ID          string    `json:"id"`
	OwnerID     string    `json:"owner_id"`
	BotID       string    `json:"bot_id,omitempty"`
	ChannelType string    `json:"channel_type"`
	Destination string    `json:"destination"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Store interface {
	ListChannelsForOwner(ctx context.Context, ownerID string) ([]NotificationChannel, error)
	ListChannelsForBot(ctx context.Context, botID string) ([]NotificationChannel, error)
	GetChannel(ctx context.Context, id string) (*NotificationChannel, error)
	CreateChannel(ctx context.Context, ch *NotificationChannel) error
	UpdateChannel(ctx context.Context, id string, channelType, destination string, enabled bool) error
	DeleteChannel(ctx context.Context, id string) error
	CheckCooldown(ctx context.Context, botID, pattern string) (bool, error)
	RecordNotification(ctx context.Context, botID, method, pattern string, cooldownUntil time.Time) error
	ListRecentDenials(ctx context.Context) (map[string][]DenialInfo, error)
	MarkDigested(ctx context.Context, botID string) error
}

type PGStore struct {
	pool *pgxpool.Pool
}

func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

func (s *PGStore) ListChannelsForOwner(ctx context.Context, ownerID string) ([]NotificationChannel, error) {
	var query string
	var args []interface{}
	if ownerID == "" {
		query = `SELECT id, owner_id, COALESCE(bot_id, ''), channel_type, destination, enabled, created_at, updated_at
			FROM notification_channels ORDER BY created_at DESC`
	} else {
		query = `SELECT id, owner_id, COALESCE(bot_id, ''), channel_type, destination, enabled, created_at, updated_at
			FROM notification_channels WHERE owner_id = $1 ORDER BY created_at DESC`
		args = append(args, ownerID)
	}
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChannels(rows)
}

func (s *PGStore) ListChannelsForBot(ctx context.Context, botID string) ([]NotificationChannel, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT nc.id, nc.owner_id, COALESCE(nc.bot_id, ''), nc.channel_type, nc.destination, nc.enabled, nc.created_at, nc.updated_at
		FROM notification_channels nc
		JOIN user_managers um ON um.manager_id = nc.owner_id
		WHERE um.bot_id = $1
		  AND nc.enabled = TRUE
		  AND (nc.bot_id = $1 OR nc.bot_id IS NULL)
	`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChannels(rows)
}

func (s *PGStore) GetChannel(ctx context.Context, id string) (*NotificationChannel, error) {
	var ch NotificationChannel
	err := s.pool.QueryRow(ctx, `
		SELECT id, owner_id, COALESCE(bot_id, ''), channel_type, destination, enabled, created_at, updated_at
		FROM notification_channels WHERE id = $1
	`, id).Scan(&ch.ID, &ch.OwnerID, &ch.BotID, &ch.ChannelType, &ch.Destination, &ch.Enabled, &ch.CreatedAt, &ch.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &ch, nil
}

func (s *PGStore) CreateChannel(ctx context.Context, ch *NotificationChannel) error {
	ch.ID = db.NewID("notch")
	var botID *string
	if ch.BotID != "" {
		botID = &ch.BotID
	}
	return s.pool.QueryRow(ctx, `
		INSERT INTO notification_channels(id, owner_id, bot_id, channel_type, destination)
		VALUES($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`, ch.ID, ch.OwnerID, botID, ch.ChannelType, ch.Destination).Scan(&ch.CreatedAt, &ch.UpdatedAt)
}

func (s *PGStore) UpdateChannel(ctx context.Context, id string, channelType, destination string, enabled bool) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE notification_channels
		SET channel_type = $2, destination = $3, enabled = $4, updated_at = NOW()
		WHERE id = $1
	`, id, channelType, destination, enabled)
	return err
}

func (s *PGStore) DeleteChannel(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errNotFound
	}
	return nil
}

func (s *PGStore) CheckCooldown(ctx context.Context, botID, pattern string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM denial_notifications
			WHERE bot_id = $1 AND url_pattern = $2 AND cooldown_until > NOW()
		)
	`, botID, pattern).Scan(&exists)
	return exists, err
}

func (s *PGStore) RecordNotification(ctx context.Context, botID, method, pattern string, cooldownUntil time.Time) error {
	id := db.NewID("dnot")
	_, err := s.pool.Exec(ctx, `
		INSERT INTO denial_notifications(id, bot_id, method, url_pattern, cooldown_until)
		VALUES($1, $2, $3, $4, $5)
		ON CONFLICT(bot_id, url_pattern) DO UPDATE
		SET notified_at = NOW(), method = EXCLUDED.method, cooldown_until = EXCLUDED.cooldown_until
	`, id, botID, method, pattern, cooldownUntil)
	return err
}

func scanChannels(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close()
	Err() error
}) ([]NotificationChannel, error) {
	var result []NotificationChannel
	for rows.Next() {
		var ch NotificationChannel
		if err := rows.Scan(&ch.ID, &ch.OwnerID, &ch.BotID, &ch.ChannelType, &ch.Destination, &ch.Enabled, &ch.CreatedAt, &ch.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, ch)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if result == nil {
		result = []NotificationChannel{}
	}
	return result, nil
}

var errNotFound = fmt.Errorf("not found")

// ListRecentDenials returns denials grouped by bot_id that haven't been digested yet.
func (s *PGStore) ListRecentDenials(ctx context.Context) (map[string][]DenialInfo, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT bot_id, method, url_pattern FROM denial_notifications
		WHERE digested_at IS NULL OR notified_at > digested_at
		ORDER BY bot_id, notified_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]DenialInfo)
	for rows.Next() {
		var botID, method, pattern string
		if err := rows.Scan(&botID, &method, &pattern); err != nil {
			return nil, err
		}
		result[botID] = append(result[botID], DenialInfo{Method: method, Pattern: pattern})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// MarkDigested marks all denial_notifications for a bot as included in a digest.
func (s *PGStore) MarkDigested(ctx context.Context, botID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE denial_notifications SET digested_at = NOW()
		WHERE bot_id = $1 AND (digested_at IS NULL OR notified_at > digested_at)
	`, botID)
	return err
}

// ManagersForBot implements ManagerResolver by querying user_managers.
func (s *PGStore) ManagersForBot(ctx context.Context, botID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT manager_id FROM user_managers WHERE bot_id = $1
	`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}
