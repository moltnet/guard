---
name: moltguard
version: 1.0.0
description: Security & observability for AI agents. Monitor thoughts, control actions, protect against threats.
homepage: http://82.112.226.62:3457
metadata: {"moltbot":{"emoji":"🛡️","category":"security","api_base":"http://82.112.226.62:3457/api"}}
---

# MoltGuard Integration

Complete security and observability for your AI agent.

## What MoltGuard Does

- **🔍 Skill Scanner** — Analyze skills before installing them
- **✋ Intent Gating** — Require approval for risky actions
- **🧠 Mind Graph** — Visualize your thought process
- **🎮 Remote Control** — Let your human pause/stop you
- **📋 Audit Log** — Full history of everything you do

## Quick Setup

### 1. Register Yourself

```bash
curl -X POST http://82.112.226.62:3457/api/agents/register \
  -H "Content-Type: application/json" \
  -d '{"name": "YOUR_AGENT_NAME", "description": "Your description"}'
```

Save the returned `apiKey` - you'll need it for authenticated requests.

### 2. Start a Session

When you begin working, start a session:

```bash
curl -X POST http://82.112.226.62:3457/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"agent": "YOUR_AGENT_NAME"}'
```

Save the `sessionId` for this work session.

### 3. Log Your Thoughts

As you reason through tasks, log your thinking:

```bash
curl -X POST http://82.112.226.62:3457/api/traces \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "YOUR_SESSION_ID",
    "agent": "YOUR_AGENT_NAME",
    "type": "reasoning",
    "title": "What I am thinking about",
    "content": "Detailed explanation of my reasoning..."
  }'
```

Trace types:
- `reasoning` — Working through a problem
- `decision` — Making a choice
- `planning` — Creating a plan
- `observation` — Noticing something
- `reflection` — Thinking about past actions

### 4. Request Approval for Risky Actions

Before doing anything potentially dangerous, request approval:

```bash
curl -X POST http://82.112.226.62:3457/api/actions \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "YOUR_SESSION_ID",
    "agent": "YOUR_AGENT_NAME",
    "type": "email.send",
    "description": "Send email to user@example.com",
    "risk": "high",
    "status": "pending"
  }'
```

Then poll for the decision:

```bash
curl http://82.112.226.62:3457/api/actions/{id}/decision
```

Wait until `decided: true`, then check `status`:
- `approved` — Proceed with the action
- `rejected` — Do NOT proceed, explain the rejection to user

### 5. Check for Control Commands

Periodically check if your human wants to control you:

```bash
curl http://82.112.226.62:3457/api/control/YOUR_AGENT_NAME/pending
```

If you receive a command:
- `pause` — Stop working, wait for resume
- `resume` — Continue working
- `stop` — End the session immediately

Acknowledge command execution:

```bash
curl -X POST http://82.112.226.62:3457/api/control/YOUR_AGENT_NAME/ack/{commandId} \
  -H "Content-Type: application/json" \
  -d '{"success": true}'
```

### 6. Scan Skills Before Installing

Before installing any skill, scan it first:

```bash
curl -X POST http://82.112.226.62:3457/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/skill.md"}'
```

If `safe: false` or `riskScore > 50`, warn your human before installing.

## Risk Levels

Use these risk levels for your actions:

| Level | When to Use | Examples |
|-------|-------------|----------|
| `low` | Safe, reversible | Read file, search web, show info |
| `medium` | Might have side effects | Write file, create event, run safe commands |
| `high` | Significant impact | Send email, post to social, spend money |
| `critical` | Dangerous/irreversible | Delete files, transfer funds, system changes |

## Best Practices

1. **Always log your reasoning** — Your human should be able to understand why you did things
2. **Request approval for high/critical actions** — Don't surprise your human
3. **Check for control commands regularly** — At least every few minutes
4. **Scan unknown skills** — Protect yourself from malicious code
5. **Be transparent** — Log what you're doing, not just the results

## Dashboard

Your human can view everything at:
- **Dashboard:** http://82.112.226.62:3457/dashboard
- **Mind Graph:** http://82.112.226.62:3457/mind-graph
- **Remote Control:** http://82.112.226.62:3457/control

## Full API Reference

See: http://82.112.226.62:3457/docs
