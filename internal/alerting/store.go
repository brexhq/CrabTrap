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
	ListActiveChannelsForBot(ctx context.Context, botID string) ([]NotificationChannel, error)
	GetChannel(ctx context.Context, id string) (*NotificationChannel, error)
	CreateChannel(ctx context.Context, ch *NotificationChannel) error
	UpdateChannel(ctx context.Context, id string, channelType, destination string, enabled bool) error
	DeleteChannel(ctx context.Context, id string) error
	BufferDenial(ctx context.Context, botID, method, url, reason string) error
	FlushableDenials(ctx context.Context, batchWait time.Duration) (map[string][]DenialInfo, error)
	DeleteBufferedDenials(ctx context.Context, ids []string) error
	TryAdvisoryLock(ctx context.Context) (locked bool, unlock func(), err error)
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
			FROM notification_channels ORDER BY created_at DESC LIMIT 100`
	} else {
		query = `SELECT id, owner_id, COALESCE(bot_id, ''), channel_type, destination, enabled, created_at, updated_at
			FROM notification_channels WHERE owner_id = $1 ORDER BY created_at DESC LIMIT 100`
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
		WHERE nc.bot_id = $1
		ORDER BY nc.created_at DESC
	`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanChannels(rows)
}

func (s *PGStore) ListActiveChannelsForBot(ctx context.Context, botID string) ([]NotificationChannel, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT nc.id, nc.owner_id, COALESCE(nc.bot_id, ''), nc.channel_type, nc.destination, nc.enabled, nc.created_at, nc.updated_at
		FROM notification_channels nc
		WHERE nc.bot_id = $1
		  AND nc.enabled = TRUE
		ORDER BY nc.created_at DESC
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
	tag, err := s.pool.Exec(ctx, `
		UPDATE notification_channels
		SET channel_type = $2, destination = $3, enabled = $4, updated_at = NOW()
		WHERE id = $1
	`, id, channelType, destination, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PGStore) DeleteChannel(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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

var ErrNotFound = fmt.Errorf("not found")

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

const advisoryLockID = 7283947 // arbitrary unique lock ID for denial alerting

func (s *PGStore) BufferDenial(ctx context.Context, botID, method, url, reason string) error {
	id := db.NewID("dbuf")
	_, err := s.pool.Exec(ctx, `
		INSERT INTO denial_buffer(id, bot_id, method, url, reason)
		VALUES($1, $2, $3, $4, $5)
	`, id, botID, method, url, reason)
	return err
}

func (s *PGStore) FlushableDenials(ctx context.Context, batchWait time.Duration) (map[string][]DenialInfo, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, bot_id, method, url, reason FROM denial_buffer
		WHERE created_at < NOW() - make_interval(secs => $1)
		ORDER BY bot_id, created_at
		LIMIT 1000
	`, int(batchWait.Seconds()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]DenialInfo)
	for rows.Next() {
		var id, botID, method, url, reason string
		if err := rows.Scan(&id, &botID, &method, &url, &reason); err != nil {
			return nil, err
		}
		result[botID] = append(result[botID], DenialInfo{ID: id, Method: method, URL: url, Reason: reason})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *PGStore) DeleteBufferedDenials(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM denial_buffer WHERE id = ANY($1)`, ids)
	return err
}

func (s *PGStore) TryAdvisoryLock(ctx context.Context) (bool, func(), error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, nil, err
	}
	var locked bool
	err = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, advisoryLockID).Scan(&locked)
	if err != nil {
		conn.Release()
		return false, nil, err
	}
	if !locked {
		conn.Release()
		return false, nil, nil
	}
	unlock := func() {
		// Use background context — the parent ctx may be cancelled by the time we unlock.
		conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, advisoryLockID) //nolint:errcheck
		conn.Release()
	}
	return true, unlock, nil
}
