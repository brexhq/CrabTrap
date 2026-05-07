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

CREATE INDEX IF NOT EXISTS idx_notification_channels_owner ON notification_channels(owner_id);
CREATE INDEX IF NOT EXISTS idx_notification_channels_bot ON notification_channels(bot_id) WHERE bot_id IS NOT NULL;

-- Tracks which (bot, url_pattern) pairs have been notified recently for dedup.
CREATE TABLE IF NOT EXISTS denial_notifications (
    id             TEXT PRIMARY KEY,
    bot_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url_pattern    TEXT NOT NULL,
    notified_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cooldown_until TIMESTAMPTZ NOT NULL,
    UNIQUE(bot_id, url_pattern)
);

CREATE INDEX IF NOT EXISTS idx_denial_notifications_bot ON denial_notifications(bot_id);
