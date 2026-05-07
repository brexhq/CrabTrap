# Denial Alerting

CrabTrap can notify bot managers when their bots are being denied. Denials are buffered for a configurable window, then summarized by an LLM and sent as a single notification — giving managers the context to decide whether to update the policy or investigate.

## How It Works

1. A bot's request is denied
2. The denial is added to a per-bot buffer
3. After the batch window (default 5 minutes), the buffer is flushed
4. The LLM summarizes all buffered denials into a 2-3 sentence explanation
5. One notification is sent to the bot's managers via their configured channels

This means a bot that gets denied on 10 different endpoints in quick succession produces ONE notification with full context — not 10 separate alerts.

## Configuration

```yaml
alerting:
  enabled: true
  batch_window: 5m   # time after first denial before sending (default 5m)
  slack:
    bot_token: "${CRABTRAP_SLACK_BOT_TOKEN}"
```

Alerting requires the LLM judge to be enabled (it uses the fast model for summarization).

## Slack Setup

1. Create a Slack app at https://api.slack.com/apps
2. Add the `chat:write` bot scope under OAuth & Permissions
3. Install the app to your workspace
4. Copy the Bot User OAuth Token (starts with `xoxb-`)
5. Set it as `CRABTRAP_SLACK_BOT_TOKEN` in your environment
6. Invite the bot to channels where you want alerts: `/invite @CrabTrap`

## Managing Notification Channels

Managers configure where alerts go via the bot detail page in the web UI, or via the API:

```bash
# Create a notification channel for a bot
curl -X POST http://localhost:8081/admin/notification-channels \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"bot_id": "my-agent@company.com", "channel_type": "slack", "destination": "#agent-alerts"}'

# Test the channel
curl -X POST http://localhost:8081/admin/notification-channels/notch_abc123/test \
  -H "Authorization: Bearer $TOKEN"
```

## What Managers See

```
:rotating_light: Denial summary for bot-a@company.com (5 blocked requests in last 5m)

The bot attempted to create a GitHub repository, trigger a deployment,
and notify the team via Slack. The current policy blocks write access
to all three services. This appears to be a deploy workflow that needs
policy access to github.com repos API and slack.com messaging API.

Requests blocked:
• POST https://api.github.com/repos/org/new-repo
• POST https://api.github.com/repos/org/new-repo/deployments
• POST https://slack.com/api/chat.postMessage (3x)
```

## Adding Custom Channel Types

Implement the `Sender` interface and register at startup:

```go
type Sender interface {
    Send(ctx context.Context, destination string, msg Message) error
}
alertService.RegisterSender("pagerduty", myPagerDutySender)
```

## Authorization

- **Managers** can create/update/delete notification channels for bots they manage
- **Admins** can manage any notification channel
- Creating a channel linked to a bot requires being a manager of that bot
