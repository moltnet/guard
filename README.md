# 🛡️ MoltGuard

**Security & observability platform for AI agents.**

Complete visibility and control over your AI agents. See what they're thinking, approve risky actions, stop them when needed.

## 🌐 Live Demo

**[http://82.112.226.62:3457](http://82.112.226.62:3457)**

## ✨ Features

### 🔍 Skill Scanner
Analyze skills for malicious patterns before installation:
- Remote code execution detection
- Data exfiltration patterns
- Credential access attempts
- Obfuscation detection
- Supply chain risks

### 🧠 Mind Graph
Visualize what your agent is thinking:
- Real-time thought logging
- Decision tree visualization
- Session timeline
- Reasoning trace

### ✋ Intent Gating
Require approval for risky actions:
- Pending action queue
- Approve/reject workflow
- Auto-timeout
- Webhook callbacks
- Telegram notifications

### 🎮 Remote Control
Control your agents in real-time:
- Pause / Resume
- Emergency Stop
- Command history
- Multi-agent management

### 📋 Audit Log
Complete action history:
- Search and filter
- Export (JSON/CSV)
- Cost tracking
- Token usage

### 🏷️ Badges
Show skill safety in your README:
```markdown
![MoltGuard](http://82.112.226.62:3457/api/badge?url=YOUR_SKILL_URL)
```

## 📄 Pages

| Page | Description |
|------|-------------|
| `/` | Landing page with quick scan |
| `/scan` | Single skill scanner |
| `/batch` | Batch scan (up to 10) |
| `/compare` | Side-by-side comparison |
| `/dashboard` | Activity log & stats |
| `/mind-graph` | Thought visualization |
| `/control` | Remote agent control |
| `/architecture` | How it works |
| `/docs` | API documentation |
| `/skill.md` | Clawdbot integration skill |

## 🔌 API Endpoints

### Skill Scanner
- `POST /api/scan` — Scan a skill
- `POST /api/batch-scan` — Scan multiple skills
- `POST /api/compare` — Compare two skills
- `GET /api/badge?url=` — Get SVG badge

### Action Logging
- `POST /api/actions` — Log an action
- `GET /api/pending` — Get pending actions
- `POST /api/actions/:id/approve` — Approve
- `POST /api/actions/:id/reject` — Reject

### Mind Graph
- `POST /api/sessions` — Start session
- `POST /api/traces` — Log thought
- `GET /api/mind-graph/:sessionId` — Get graph data

### Remote Control
- `POST /api/agents/register` — Register agent
- `POST /api/control/:agent` — Send command
- `GET /api/control/:agent/pending` — Get commands

## 🚀 Quick Start

### For AI Agents (Clawdbot/OpenClaw)

1. **Register your agent:**
```bash
curl -X POST http://82.112.226.62:3457/api/agents/register \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent", "description": "My AI assistant"}'
```

2. **Log your thoughts:**
```bash
curl -X POST http://82.112.226.62:3457/api/traces \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "my-agent",
    "type": "reasoning",
    "title": "Analyzing request",
    "content": "User wants me to..."
  }'
```

3. **Request approval for risky actions:**
```bash
curl -X POST http://82.112.226.62:3457/api/actions \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "my-agent",
    "type": "email.send",
    "description": "Send report",
    "risk": "high",
    "status": "pending"
  }'
```

4. **Check for control commands:**
```bash
curl http://82.112.226.62:3457/api/control/my-agent/pending
```

### For Humans

1. Open http://82.112.226.62:3457
2. View your agent's activity in the Dashboard
3. See their thinking in Mind Graph
4. Control them from Remote Control

## 🔧 Self-Hosting

```bash
git clone https://github.com/rohansx/moltguard
cd moltguard
npm install
npm start
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3457 |
| `MOLTGUARD_API_KEY` | API authentication | none |
| `TELEGRAM_BOT_TOKEN` | Telegram alerts | none |
| `TELEGRAM_CHAT_ID` | Telegram chat | none |
| `PENDING_TIMEOUT_MS` | Auto-reject timeout | 300000 |

## 📊 Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  AI Agent   │ ───▶ │  MoltGuard  │ ◀─── │    Human    │
│  (Clawdbot) │      │  (Security) │      │ (Dashboard) │
└─────────────┘      └─────────────┘      └─────────────┘
       │                    │                    │
       │  Logs thoughts     │  Stores data       │  Views activity
       │  Requests approval │  Sends alerts      │  Approves/rejects
       │  Checks commands   │  Enforces policy   │  Sends commands
       ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────────┐
│                     SQLite Database                      │
│  actions | traces | sessions | agents | commands | scans │
└─────────────────────────────────────────────────────────┘
```

## 📄 License

MIT

---

Built with ⚡ by [@rohansxd](https://twitter.com/rohansxd)
