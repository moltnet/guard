# @moltnet/guard

**MoltGuard plugin for Clawdbot** — Security & observability for AI agents.

[![MoltGuard](https://guard.moltnet.ai/api/badge?label=moltguard&status=secure)](https://guard.moltnet.ai)

## Features

- 🔍 **Action Logging** — Every tool call is logged with risk classification
- 🧠 **Mind Graph** — Visualize your agent's thought process in real-time
- ✋ **Intent Gating** — Require approval for high-risk actions
- 🎮 **Remote Control** — Pause, resume, or stop your agent remotely
- 📊 **Audit Dashboard** — Complete history with search, filters, and export

## Installation

```bash
clawdbot plugins install @moltnet/guard
```

## Configuration

1. **Get your token** at [guard.moltnet.ai](https://guard.moltnet.ai)

2. **Add to your Clawdbot config** (`~/.clawdbot/config.json`):

```json
{
  "plugins": {
    "entries": {
      "guard": {
        "enabled": true,
        "config": {
          "token": "mg_your_token_here",
          "agentName": "my-assistant"
        }
      }
    }
  }
}
```

3. **Restart Clawdbot**

```bash
clawdbot gateway restart
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `token` | string | **required** | Your MoltGuard API token |
| `url` | string | `https://guard.moltnet.ai` | MoltGuard server URL |
| `agentName` | string | `clawdbot-<hostname>` | Display name in dashboard |
| `logThoughts` | boolean | `true` | Send reasoning traces to Mind Graph |
| `gateHighRisk` | boolean | `true` | Require approval for high-risk actions |
| `gateTools` | string[] | `["exec", "message", "write"]` | Tools that require approval |
| `pollCommands` | boolean | `true` | Enable remote control (pause/resume/stop) |
| `pollIntervalMs` | number | `5000` | Command poll interval in ms |

## Risk Classification

The plugin automatically classifies tool calls by risk:

| Risk | Tools |
|------|-------|
| 🔴 **Critical** | `gateway`, `exec` (with `rm`, `sudo`) |
| 🟠 **High** | `exec`, `message`, `nodes` |
| 🟡 **Medium** | `write`, `edit`, `browser`, `cron`, `process` |
| 🟢 **Low** | `read`, `web_search`, `web_fetch`, `memory_*` |

## How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Clawdbot     │────▶│   MoltGuard     │◀────│     Human       │
│    (Agent)      │     │   Plugin        │     │   (Dashboard)   │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │  guard.moltnet  │
                        │     .ai         │
                        └─────────────────┘
```

1. Plugin intercepts all tool calls via `tool_result_persist` hook
2. Actions are logged to MoltGuard with risk classification
3. High-risk actions wait for approval (if `gateHighRisk` enabled)
4. Human approves/rejects from dashboard or Telegram
5. Plugin polls for remote control commands

## Self-Hosting

If you're running your own MoltGuard instance:

```json
{
  "plugins": {
    "entries": {
      "guard": {
        "enabled": true,
        "config": {
          "url": "https://your-moltguard.com",
          "token": "your_token"
        }
      }
    }
  }
}
```

## Links

- **Dashboard:** [guard.moltnet.ai](https://guard.moltnet.ai)
- **Docs:** [guard.moltnet.ai/docs](https://guard.moltnet.ai/docs)
- **GitHub:** [github.com/moltnet/guard](https://github.com/moltnet/guard)

## License

MIT
