# MoltGuard Architecture

**Security & Observability Platform for AI Agents**

> Complete visibility and control over your AI agents. See what they're thinking, approve risky actions, stop them when needed.

---

## 🎯 Vision

MoltGuard is the security layer for the AI agent ecosystem. As autonomous agents proliferate, humans need:
1. **Visibility** – What is my agent doing? What is it thinking?
2. **Control** – Can I pause, approve, or stop it?
3. **Safety** – Is this skill/code safe to install?
4. **Audit** – What happened? Who approved it? How much did it cost?

---

## 🏛️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  Landing    │   Scanner   │   Dashboard  │  Mind Graph │  Remote Control    │
│  /          │   /scan     │   /dashboard │  /mind-graph│  /control          │
│  Quick scan │   Deep scan │   Activity   │  Thought    │  Pause/Resume/     │
│  Hero       │   Batch     │   Stats      │  Visualizer │  Stop agents       │
│             │   Compare   │   Audit log  │             │                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              REST API LAYER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  /api/scan         - Skill security scanning                                 │
│  /api/actions      - Action logging & approval workflows                     │
│  /api/traces       - Thought/reasoning logging                               │
│  /api/sessions     - Session lifecycle management                            │
│  /api/agents       - Agent registry                                          │
│  /api/control      - Remote commands (pause/resume/stop)                     │
│  /api/badge        - SVG badges for README files                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CORE SERVICES                                       │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────────┤
│ SkillScanner │ ActionGate   │ MindGraph    │ CommandCtrl  │ NotificationSvc │
│              │              │              │              │                 │
│ Pattern      │ Pending Q    │ Trace trees  │ Agent reg    │ Telegram alerts │
│ detection    │ Approve/Rej  │ Session mgmt │ Cmd dispatch │ Callbacks       │
│ Risk scoring │ Auto-timeout │ Visualization│ Heartbeat    │ Webhooks        │
│ Code-aware   │ Undo system  │ Timeline     │ ACK/NACK     │                 │
└──────────────┴──────────────┴──────────────┴──────────────┴─────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DATA LAYER (SQLite)                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  actions        │ Logged actions with status, risk, cost                     │
│  skill_scans    │ Cached scan results                                        │
│  agent_sessions │ Session tracking                                           │
│  traces         │ Thought/reasoning traces (parent-child tree)               │
│  commands       │ Remote control command queue                               │
│  agents         │ Registered agent registry                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Feature Modules

### 1. 🔍 Skill Scanner

**Purpose:** Analyze AI agent skills/plugins for security risks before installation.

**How it works:**
```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│ Skill URL   │ ──▶ │ Fetch SKILL  │ ──▶ │ Code Block   │ ──▶ │ Pattern     │
│ or Content  │     │ .md Content  │     │ Extraction   │     │ Matching    │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
                                                                     │
                                                                     ▼
                                         ┌──────────────┐     ┌─────────────┐
                                         │ Risk Score   │ ◀── │ Severity    │
                                         │ Calculation  │     │ Weighting   │
                                         └──────────────┘     └─────────────┘
```

**Pattern Categories:**

| Category | Severity | Examples |
|----------|----------|----------|
| **Critical Patterns** | 🔴 35pts | `curl \| sh`, reverse shells, `rm -rf /` |
| **Context Patterns** | 🟠 15-30pts | SSH key access, wallet reads (in code blocks only) |
| **Info Patterns** | 🟡 3-8pts | `sudo`, base64 decode, inline scripts |
| **Suspicious URLs** | 🟠 12pts | Pastebin, URL shorteners, ngrok |
| **Obfuscation** | 🟠 18-22pts | Long base64, hex-encoded strings |

**Risk Levels:**
- `safe` (0-19): ✅ No significant issues
- `low` (1-19): 🟢 Minor concerns
- `medium` (20-44): 🟡 Review recommended
- `high` (45-69): 🟠 Careful review required
- `critical` (70+): 🔴 Do not install without audit

**API Endpoints:**
- `POST /api/scan` – Single skill scan
- `POST /api/batch-scan` – Batch scan (up to 10)
- `POST /api/compare` – Side-by-side comparison
- `GET /api/badge?url=` – Dynamic SVG badge

---

### 2. ✋ Intent Gating (Action Approval)

**Purpose:** Require human approval for risky AI agent actions.

**Workflow:**
```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ Agent logs  │ ──▶ │ Risk = High? │ ──▶ │ Status =     │
│ action      │     │ Status =     │     │ PENDING      │
│ (via API)   │     │ pending?     │     │              │
└─────────────┘     └──────────────┘     └──────────────┘
                           │                    │
                           ▼                    ▼
                    ┌──────────────┐     ┌──────────────┐
                    │ Telegram     │     │ Human        │
                    │ Notification │     │ Dashboard    │
                    └──────────────┘     └──────────────┘
                                               │
                           ┌───────────────────┴───────────────────┐
                           ▼                                       ▼
                    ┌──────────────┐                        ┌──────────────┐
                    │ ✅ APPROVED  │                        │ ❌ REJECTED  │
                    │ Callback     │                        │ Callback     │
                    └──────────────┘                        └──────────────┘
                                               │
                                               ▼ (if timeout)
                                        ┌──────────────┐
                                        │ ⏰ TIMEOUT   │
                                        │ Auto-reject  │
                                        └──────────────┘
```

**Action Schema:**
```json
{
  "id": "abc123",
  "agent": "my-agent",
  "type": "email.send",
  "description": "Send report to boss@company.com",
  "risk": "high",
  "status": "pending",
  "cost_usd": 0.02,
  "tokens_in": 1500,
  "tokens_out": 500,
  "reversible": true,
  "undo_action": "{ \"type\": \"email.delete\", ... }",
  "callback_url": "https://my-agent/callback"
}
```

**API Endpoints:**
- `POST /api/actions` – Log an action
- `GET /api/pending` – Get pending actions
- `POST /api/actions/:id/approve` – Approve
- `POST /api/actions/:id/reject` – Reject with reason
- `POST /api/actions/:id/undo` – Undo reversible action
- `POST /api/bulk/approve` – Bulk approve
- `POST /api/bulk/reject` – Bulk reject

---

### 3. 🧠 Mind Graph (Thought Visualization)

**Purpose:** See what your agent is thinking in real-time.

**Data Model:**
```
┌─────────────────────────────────────────────────────────────────┐
│                         SESSION                                   │
│  id: "sess_abc"                                                  │
│  agent: "my-agent"                                               │
│  started_at: "2026-01-30T12:00:00Z"                              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  ┌───────────┐           ┌───────────┐           ┌───────────┐
  │ TRACE     │           │ TRACE     │           │ ACTION    │
  │ reasoning │           │ decision  │           │ file.read │
  │ depth: 0  │           │ depth: 0  │           │ status:   │
  │           │           │           │           │ completed │
  └─────┬─────┘           └───────────┘           └───────────┘
        │
        ├──────────────────────┐
        ▼                      ▼
  ┌───────────┐          ┌───────────┐
  │ TRACE     │          │ TRACE     │
  │ analysis  │          │ plan      │
  │ depth: 1  │          │ depth: 1  │
  └───────────┘          └───────────┘
```

**Trace Types:**
- `reasoning` – Thinking/analysis
- `decision` – Choice made
- `observation` – Information gathered
- `action` – Tool/action executed
- `error` – Something went wrong
- `question` – Agent is uncertain

**API Endpoints:**
- `POST /api/sessions` – Start a session
- `POST /api/sessions/:id/end` – End session
- `POST /api/traces` – Log a thought
- `GET /api/mind-graph/:sessionId` – Get graph data

---

### 4. 🎮 Remote Control

**Purpose:** Control agents in real-time (pause, resume, stop, inject commands).

**Command Flow:**
```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ Human sends │ ──▶ │ Command      │ ──▶ │ Agent polls  │
│ command     │     │ queued       │     │ /pending     │
└─────────────┘     └──────────────┘     └──────────────┘
                                               │
                                               ▼
                                        ┌──────────────┐
                                        │ Agent ACKs   │
                                        │ execution    │
                                        └──────────────┘
```

**Commands:**
| Command | Description |
|---------|-------------|
| `pause` | Pause agent execution |
| `resume` | Resume from pause |
| `stop` | Emergency stop |
| `inject` | Inject a message/instruction |
| `config` | Update agent config |

**API Endpoints:**
- `POST /api/agents/register` – Register agent
- `POST /api/control/:agent` – Send command
- `GET /api/control/:agent/pending` – Poll for commands
- `POST /api/control/:agent/ack/:commandId` – Acknowledge execution

---

### 5. 📋 Audit Log & Dashboard

**Purpose:** Complete history of all agent actions with search, filter, and export.

**Features:**
- Real-time activity feed
- Filter by agent, risk, status, type
- 24-hour activity histogram
- Cost tracking (tokens + USD)
- Export to JSON/CSV
- Detailed action modal

**Stats Available:**
```json
{
  "total": 1234,
  "by_risk": {
    "low": 800,
    "medium": 300,
    "high": 100,
    "critical": 34
  },
  "by_status": {
    "approved": 900,
    "rejected": 50,
    "pending": 10,
    "timeout": 274
  },
  "total_cost_usd": 12.45,
  "total_tokens": 2500000
}
```

---

### 6. 🏷️ Badges

**Purpose:** Show skill safety status in README files.

**Usage:**
```markdown
![MoltGuard Scan](https://guard.moltnet.ai/api/badge?url=YOUR_SKILL_URL)
```

**Badge Variants:**
- 🟢 `SAFE` – Green badge, score 0-19
- 🟡 `CAUTION` – Yellow badge, score 20-44
- 🟠 `RISKY` – Orange badge, score 45-69
- 🔴 `DANGER` – Red badge, score 70+
- ⚫ `ERROR` – Gray badge, fetch failed

---

## 🗄️ Database Schema

```sql
-- Agent registry
CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  registered_at TEXT,
  last_seen TEXT,
  status TEXT DEFAULT 'active',
  config TEXT,
  capabilities TEXT
);

-- Sessions (for mind graph)
CREATE TABLE agent_sessions (
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  status TEXT DEFAULT 'active',
  total_actions INTEGER DEFAULT 0,
  total_thoughts INTEGER DEFAULT 0,
  metadata TEXT
);

-- Thought traces (hierarchical)
CREATE TABLE traces (
  id TEXT PRIMARY KEY,
  session_id TEXT,
  timestamp TEXT NOT NULL,
  agent TEXT NOT NULL,
  type TEXT NOT NULL,          -- reasoning, decision, action, etc.
  title TEXT,
  content TEXT,
  parent_id TEXT,              -- For nested thoughts
  depth INTEGER DEFAULT 0,
  duration_ms INTEGER,
  status TEXT DEFAULT 'complete',
  metadata TEXT
);

-- Actions (with approval workflow)
CREATE TABLE actions (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  session_id TEXT,
  agent TEXT NOT NULL,
  type TEXT NOT NULL,
  description TEXT NOT NULL,
  details TEXT,
  risk TEXT NOT NULL,          -- low, medium, high, critical
  status TEXT NOT NULL,        -- pending, approved, rejected, timeout
  context TEXT,
  reversible INTEGER DEFAULT 0,
  cost_usd REAL DEFAULT 0,
  tokens_in INTEGER DEFAULT 0,
  tokens_out INTEGER DEFAULT 0,
  duration_ms INTEGER DEFAULT 0,
  decided_at TEXT,
  decided_by TEXT,
  reject_reason TEXT,
  callback_url TEXT,
  undo_action TEXT,
  undone INTEGER DEFAULT 0,
  undone_at TEXT
);

-- Skill scan results (cached)
CREATE TABLE skill_scans (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  skill_url TEXT,
  skill_name TEXT,
  skill_content TEXT,
  risk_score INTEGER,
  findings TEXT,               -- JSON array
  safe INTEGER DEFAULT 0
);

-- Remote control commands
CREATE TABLE commands (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  agent TEXT NOT NULL,
  session_id TEXT,
  command TEXT NOT NULL,       -- pause, resume, stop, inject
  params TEXT,
  status TEXT DEFAULT 'pending',
  executed_at TEXT,
  result TEXT
);
```

---

## 🔌 Integration Flow

### For AI Agents (SDK Integration)

```javascript
// 1. Register agent on startup
const { apiKey } = await fetch('/api/agents/register', {
  method: 'POST',
  body: JSON.stringify({ name: 'my-agent', description: 'My AI assistant' })
}).then(r => r.json());

// 2. Start a session
const { id: sessionId } = await fetch('/api/sessions', {
  method: 'POST',
  body: JSON.stringify({ agent: 'my-agent' })
}).then(r => r.json());

// 3. Log thoughts (for mind graph)
await fetch('/api/traces', {
  method: 'POST',
  body: JSON.stringify({
    sessionId,
    agent: 'my-agent',
    type: 'reasoning',
    title: 'Analyzing user request',
    content: 'User wants me to send an email...'
  })
});

// 4. Request approval for risky action
const action = await fetch('/api/actions', {
  method: 'POST',
  body: JSON.stringify({
    agent: 'my-agent',
    sessionId,
    type: 'email.send',
    description: 'Send weekly report to team',
    risk: 'high',
    status: 'pending',
    callback_url: 'https://my-agent/callback'
  })
}).then(r => r.json());

// 5. Poll for decision (or wait for callback)
const decision = await fetch(`/api/actions/${action.id}/decision`).then(r => r.json());
if (decision.status === 'approved') {
  // Proceed with action
}

// 6. Check for control commands
const commands = await fetch('/api/control/my-agent/pending').then(r => r.json());
for (const cmd of commands) {
  if (cmd.command === 'pause') { /* pause */ }
  if (cmd.command === 'stop') { /* stop */ }
  // ACK the command
  await fetch(`/api/control/my-agent/ack/${cmd.id}`, { method: 'POST' });
}
```

---

## 🎨 UI Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Landing | Hero + quick scan input |
| `/scan` | Scanner | Deep skill analysis |
| `/scan/:id` | Scan Result | Shareable scan page |
| `/batch` | Batch Scan | Scan up to 10 skills |
| `/compare` | Compare | Side-by-side skill comparison |
| `/dashboard` | Dashboard | Activity log + stats |
| `/mind-graph` | Mind Graph | Thought visualization |
| `/control` | Remote Control | Agent management |
| `/architecture` | Architecture | How it works |
| `/docs` | API Docs | Full API reference |
| `/skill.md` | Clawdbot Skill | Integration instructions |

---

## 🚀 Deployment

**Current Production:**
- **URL:** https://guard.moltnet.ai
- **Service:** systemd (`moltguard.service`)
- **Database:** `~/.moltguard/moltguard.db`
- **Port:** 3457

**Environment Variables:**
```bash
PORT=3457                      # Server port
MOLTGUARD_API_KEY=             # Optional API auth
TELEGRAM_BOT_TOKEN=            # For alerts
TELEGRAM_CHAT_ID=              # For alerts
PENDING_TIMEOUT_MS=300000      # 5 min auto-reject
```

---

## 📊 What's Built vs Roadmap

### ✅ Built (v1.0)

| Feature | Status |
|---------|--------|
| Skill Scanner (single) | ✅ |
| Skill Scanner (batch) | ✅ |
| Skill Comparison | ✅ |
| Dynamic Badges | ✅ |
| Action Logging | ✅ |
| Pending Queue | ✅ |
| Approve/Reject Flow | ✅ |
| Auto-Timeout | ✅ |
| Undo System | ✅ |
| Mind Graph | ✅ |
| Session Management | ✅ |
| Remote Control | ✅ |
| Telegram Notifications | ✅ |
| Webhook Callbacks | ✅ |
| Cost Tracking | ✅ |
| Activity Dashboard | ✅ |
| Audit Log | ✅ |
| Rate Limiting | ✅ |
| API Docs Page | ✅ |
| Terminal UI Theme | ✅ |

### 🔜 Roadmap (v2.0+)

| Feature | Priority |
|---------|----------|
| Clawdbot SDK/Skill | 🔥 High |
| Policy Engine (rules) | 🔥 High |
| Multi-user Auth | 🟡 Medium |
| HTTPS/TLS | 🟡 Medium |
| GitHub Action | 🟡 Medium |
| VS Code Extension | 🟢 Low |
| PostgreSQL Support | 🟢 Low |
| Real-time WebSocket | 🟢 Low |

---

## 📝 Tech Stack

- **Runtime:** Node.js 22+
- **Framework:** Express.js
- **Database:** SQLite (better-sqlite3)
- **ID Generation:** nanoid
- **UI:** Vanilla HTML/CSS/JS (terminal aesthetic)
- **Styling:** Monospace fonts, scanline effects, hacker vibes

---

*Built with ⚡ by [@rohansxd](https://twitter.com/rohansxd)*
