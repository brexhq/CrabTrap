-- Add role column to users table, replacing the boolean is_admin flag.
-- The role column supports three values: 'admin', 'manager', 'user'.
-- is_admin is kept for now to allow zero-downtime rollout; a later migration drops it.

ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';

UPDATE users SET role = 'admin' WHERE is_admin = TRUE AND role = 'user';

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
