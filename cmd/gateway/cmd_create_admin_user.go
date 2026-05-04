package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	idb "github.com/brexhq/CrabTrap/internal/db"
)

// runCreateAdminUser implements the "create-admin-user" subcommand.
// It upserts a user as admin and sets (or replaces) their web token.
//
// Usage:
//
//	gateway create-admin-user <user-id>
//
// DATABASE_URL must be set in the environment.
func runCreateAdminUser(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: gateway create-admin-user <user-id>")
		os.Exit(1)
	}
	userID := args[0]

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL environment variable is required")
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := idb.Open(ctx, dsn, 5, 1)
	if err != nil {
		slog.Error("failed to connect", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := idb.Migrate(ctx, pool); err != nil {
		slog.Error("failed to migrate", "error", err)
		os.Exit(1)
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		slog.Error("failed to generate token", "error", err)
		os.Exit(1)
	}
	token := hex.EncodeToString(b)

	tx, err := pool.Begin(ctx)
	if err != nil {
		slog.Error("failed to begin tx", "error", err)
		os.Exit(1)
	}
	defer tx.Rollback(ctx)

	if _, err = tx.Exec(ctx, `
		INSERT INTO users(id, is_admin, role)
		VALUES($1, true, 'admin')
		ON CONFLICT(id) DO UPDATE SET is_admin = true, role = 'admin', updated_at = NOW()
	`, userID); err != nil {
		slog.Error("failed to upsert user", "error", err)
		os.Exit(1)
	}

	chanID := idb.NewID("chan")
	payload, _ := json.Marshal(map[string]string{"web_token": token})
	if _, err = tx.Exec(ctx, `
		INSERT INTO user_channels(id, user_id, channel_type, payload)
		VALUES($1, $2, 'web', $3)
		ON CONFLICT(user_id, channel_type) DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()
	`, chanID, userID, payload); err != nil {
		slog.Error("failed to upsert web channel", "error", err)
		os.Exit(1)
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("failed to commit", "error", err)
		os.Exit(1)
	}

	fmt.Printf("user_id:   %s\n", userID)
	fmt.Printf("web_token: %s\n", token)
}
