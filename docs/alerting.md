# Denial Alerting

CrabTrap can notify bot managers when their bots are denied access to a new URL pattern. This helps managers keep policies up to date as bots encounter new APIs.

## How It Works

When CrabTrap denies a request, the alerting system:

1. Normalizes the URL to a pattern (host + first two path segments)
2. Checks if this bot was already notified for this pattern recently
3. If new: resolves the bot's managers, finds their notification channels, and sends an alert
4. If seen recently: stays silent (dedup cooldown)

This means a bot that retries the same blocked endpoint 1000 times produces exactly one notification — not 1000.

## Configuration

```yaml
alerting:
  enabled: true
  cooldown: 1h        # don't re-notify for same (bot, pattern) within this window
  slack:
    bot_token: "${CRABTRAP_SLACK_BOT_TOKEN}"
```

The `cooldown` controls how long to suppress duplicate notifications for the same URL pattern on the same bot. After the cooldown expires, the next denial of that pattern triggers a new notification.

## Slack Setup

1. Create a Slack app at https://api.slack.com/apps
2. Add the `chat:write` bot scope under OAuth & Permissions
3. Install the app to your workspace
4. Copy the Bot User OAuth Token (starts with `xoxb-`)
5. Set it as `CRABTRAP_SLACK_BOT_TOKEN` in your environment
6. Invite the bot to any channels where you want alerts: `/invite @CrabTrap`

## Managing Notification Channels

Managers configure where their bot alerts go via the admin API:

```bash
# Create a notification channel for a specific bot
curl -X POST http://localhost:8081/admin/notification-channels \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bot_id": "my-agent@company.com", "channel_type": "slack", "destination": "#agent-alerts"}'

# Create a channel for all bots you manage (omit bot_id)
curl -X POST http://localhost:8081/admin/notification-channels \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"channel_type": "slack", "destination": "#all-bot-alerts"}'

# Test the channel
curl -X POST http://localhost:8081/admin/notification-channels/notch_abc123/test \
  -H "Authorization: Bearer $TOKEN"

# List your channels
curl http://localhost:8081/admin/notification-channels \
  -H "Authorization: Bearer $TOKEN"
```

## URL Pattern Normalization

URLs are grouped by host and the first two path segments. Query parameters, fragments, and default ports are stripped:

| Raw URL | Pattern |
|---------|---------|
| `https://api.github.com/repos/org/repo?page=2` | `api.github.com/repos/org` |
| `https://api.stripe.com:443/v1/charges` | `api.stripe.com/v1/charges` |
| `https://slack.com/api/chat.postMessage` | `slack.com/api/chat.postMessage` |

This means denials to `/repos/org/repo1` and `/repos/org/repo2` are treated as the same pattern — one notification covers both.

## Adding Custom Channel Types

The alerting system uses a `Sender` interface that can be extended with new notification backends:

```go
type Sender interface {
    Send(ctx context.Context, destination string, msg Message) error
}
```

To add a new channel type (e.g., webhook, email, PagerDuty):

1. Implement the `Sender` interface
2. Register it at startup: `alertService.RegisterSender("webhook", myWebhookSender)`
3. Users create channels with `"channel_type": "webhook"` and `"destination": "https://..."` 

The `destination` field is always a single string — its meaning depends on the channel type (Slack channel name, webhook URL, email address, etc.).

## Authorization

- **Managers** can create/update/delete notification channels for bots they manage
- **Admins** can manage any notification channel
- Creating a channel linked to a bot (`bot_id` set) requires being a manager of that bot
- Channels with no `bot_id` receive alerts for all bots the owner manages
