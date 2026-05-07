-- Notification channels: destinations where managers receive denial alerts.
-- Extensible via channel_type (slack, webhook, email, etc.).

CREATE TABLE IF NOT EXISTS notification_channels (
    id           TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bot_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
    channel_type TEXT NOT NULL,
    destination  TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_channels_unique
    ON notification_channels(owner_id, COALESCE(bot_id, ''), channel_type, destination);

CREATE INDEX IF NOT EXISTS idx_notification_channels_owner ON notification_channels(owner_id);
CREATE INDEX IF NOT EXISTS idx_notification_channels_bot ON notification_channels(bot_id) WHERE bot_id IS NOT NULL;

-- Denial buffer: accumulates denied requests for batched alerting.
-- Periodically flushed by the alerting service using pg_advisory_lock.
CREATE TABLE IF NOT EXISTS denial_buffer (
    id         TEXT PRIMARY KEY,
    bot_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method     TEXT NOT NULL DEFAULT '',
    url        TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_denial_buffer_bot_created ON denial_buffer(bot_id, created_at);
