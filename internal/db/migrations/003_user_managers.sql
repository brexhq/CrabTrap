-- Manager-bot assignment junction table.
-- Links manager users to the bots they oversee.

CREATE TABLE IF NOT EXISTS user_managers (
    id         TEXT PRIMARY KEY,  -- "mgr_xxx" (generated via db.NewID("mgr"))
    bot_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    manager_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(bot_id, manager_id)
);

CREATE INDEX IF NOT EXISTS idx_user_managers_bot_id ON user_managers(bot_id);
CREATE INDEX IF NOT EXISTS idx_user_managers_manager_id ON user_managers(manager_id);
