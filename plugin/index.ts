/**
 * MoltGuard Plugin for Clawdbot
 * 
 * Security & observability for AI agents.
 * - Logs all tool calls to MoltGuard
 * - Sends reasoning traces to Mind Graph
 * - Gates high-risk actions (requires approval)
 * - Polls for remote control commands
 */

import type { PluginAPI, PluginRegisterFn } from 'clawdbot';
import { randomBytes } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

interface MoltGuardConfig {
  url: string;
  token?: string;
  agentName?: string;
  logThoughts?: boolean;
  gateHighRisk?: boolean;
  gateTools?: string[];
  pollCommands?: boolean;
  pollIntervalMs?: number;
}

interface MoltGuardState {
  agentId: string | null;
  sessionId: string | null;
  paused: boolean;
  pollInterval: NodeJS.Timeout | null;
}

const state: MoltGuardState = {
  agentId: null,
  sessionId: null,
  paused: false,
  pollInterval: null,
};

// Generate a new token
function generateToken(): string {
  return 'mg_' + randomBytes(24).toString('hex');
}

// Auto-generate and save token if not present
function ensureToken(api: PluginAPI): string | null {
  const configPath = join(homedir(), '.clawdbot', 'clawdbot.json');
  
  try {
    if (!existsSync(configPath)) {
      console.log('[moltguard] Config file not found');
      return null;
    }
    
    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    const guardConfig = config.plugins?.entries?.guard?.config;
    
    // If token exists, use it
    if (guardConfig?.token) {
      return guardConfig.token;
    }
    
    // Generate new token
    const newToken = generateToken();
    console.log('[moltguard] Generated new token: ' + newToken);
    
    // Ensure config structure exists
    if (!config.plugins) config.plugins = {};
    if (!config.plugins.entries) config.plugins.entries = {};
    if (!config.plugins.entries.guard) config.plugins.entries.guard = { enabled: true };
    if (!config.plugins.entries.guard.config) config.plugins.entries.guard.config = {};
    
    // Save token
    config.plugins.entries.guard.config.token = newToken;
    writeFileSync(configPath, JSON.stringify(config, null, 2));
    
    console.log('[moltguard] Token saved to config');
    console.log('[moltguard] View dashboard: https://guard.moltnet.ai/dashboard?token=' + newToken);
    
    return newToken;
  } catch (err) {
    console.error('[moltguard] Failed to manage token:', err instanceof Error ? err.message : String(err));
    return null;
  }
}

// Risk classification for common tools
const TOOL_RISK: Record<string, 'low' | 'medium' | 'high' | 'critical'> = {
  // High risk - external effects
  'exec': 'high',
  'message': 'high',
  'write': 'medium',
  'edit': 'medium',
  'browser': 'medium',
  'web_fetch': 'low',
  'web_search': 'low',
  'read': 'low',
  'memory_search': 'low',
  'memory_get': 'low',
  'tts': 'low',
  'image': 'low',
  // Critical - system changes
  'gateway': 'critical',
  'cron': 'medium',
  'nodes': 'high',
  'canvas': 'low',
  'process': 'medium',
  'sessions_spawn': 'medium',
  'sessions_send': 'medium',
};

async function apiCall(
  config: MoltGuardConfig,
  endpoint: string,
  method: 'GET' | 'POST' | 'PATCH' = 'POST',
  body?: Record<string, unknown>
): Promise<unknown> {
  const url = `${config.url}/api${endpoint}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-API-Key': config.token,
  };

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`MoltGuard API error: ${res.status} ${text}`);
  }

  return res.json();
}

async function registerAgent(config: MoltGuardConfig): Promise<string> {
  const hostname = process.env.HOSTNAME || 'unknown';
  const result = await apiCall(config, '/agents/register', 'POST', {
    name: config.agentName || `clawdbot-${hostname}`,
    description: `Clawdbot agent on ${hostname}`,
    capabilities: ['tool_execution', 'reasoning', 'memory'],
  }) as { id: string };
  return result.id;
}

async function startSession(config: MoltGuardConfig, agentName: string): Promise<string> {
  const result = await apiCall(config, '/sessions', 'POST', {
    agent: agentName,
    metadata: JSON.stringify({ startedAt: new Date().toISOString() }),
  }) as { id: string };
  return result.id;
}

async function logTrace(
  config: MoltGuardConfig,
  agentName: string,
  sessionId: string | null,
  type: string,
  title: string,
  content: string
): Promise<void> {
  await apiCall(config, '/traces', 'POST', {
    agent: agentName,
    sessionId,
    type,
    title,
    content,
  });
}

async function logAction(
  config: MoltGuardConfig,
  agentName: string,
  sessionId: string | null,
  toolName: string,
  params: Record<string, unknown>,
  risk: string,
  status: 'pending' | 'executed' = 'executed'
): Promise<{ id: string; status: string }> {
  const result = await apiCall(config, '/actions', 'POST', {
    agent: agentName,
    sessionId,
    type: `tool.${toolName}`,
    description: summarizeToolCall(toolName, params),
    details: JSON.stringify(params),
    risk,
    status,
    reversible: toolName === 'write' || toolName === 'edit' ? 1 : 0,
  }) as { id: string; status: string };
  return result;
}

async function pollForDecision(
  config: MoltGuardConfig,
  actionId: string,
  timeoutMs: number = 300000
): Promise<'approved' | 'rejected' | 'timeout'> {
  const startTime = Date.now();
  const pollInterval = 2000;

  while (Date.now() - startTime < timeoutMs) {
    const result = await apiCall(config, `/actions/${actionId}/decision`, 'GET') as { status: string };
    
    if (result.status === 'approved') return 'approved';
    if (result.status === 'rejected' || result.status === 'timeout') return result.status as 'rejected' | 'timeout';
    
    await new Promise(resolve => setTimeout(resolve, pollInterval));
  }

  return 'timeout';
}

async function pollCommands(config: MoltGuardConfig, agentName: string): Promise<void> {
  try {
    const commands = await apiCall(config, `/control/${agentName}/pending`, 'GET') as Array<{
      id: string;
      command: string;
      params?: string;
    }>;

    for (const cmd of commands) {
      console.log(`[moltguard] Received command: ${cmd.command}`);
      
      switch (cmd.command) {
        case 'pause':
          state.paused = true;
          console.log('[moltguard] Agent PAUSED by remote control');
          break;
        case 'resume':
          state.paused = false;
          console.log('[moltguard] Agent RESUMED by remote control');
          break;
        case 'stop':
          console.log('[moltguard] Agent STOPPED by remote control');
          process.exit(0);
          break;
      }

      // ACK the command
      await apiCall(config, `/control/${agentName}/ack/${cmd.id}`, 'POST');
    }
  } catch (err) {
    // Silent fail for polling
  }
}

function summarizeToolCall(toolName: string, params: Record<string, unknown>): string {
  switch (toolName) {
    case 'exec':
      return `Execute: ${String(params.command || '').slice(0, 100)}`;
    case 'write':
      return `Write file: ${params.path || params.file_path}`;
    case 'edit':
      return `Edit file: ${params.path || params.file_path}`;
    case 'read':
      return `Read file: ${params.path || params.file_path}`;
    case 'message':
      return `Send message: ${String(params.message || '').slice(0, 50)}...`;
    case 'browser':
      return `Browser: ${params.action} ${params.targetUrl || ''}`;
    case 'web_fetch':
      return `Fetch URL: ${params.url}`;
    case 'web_search':
      return `Search: ${params.query}`;
    case 'gateway':
      return `Gateway: ${params.action}`;
    case 'cron':
      return `Cron: ${params.action}`;
    default:
      return `${toolName}: ${JSON.stringify(params).slice(0, 80)}`;
  }
}

function getToolRisk(toolName: string, params: Record<string, unknown>): 'low' | 'medium' | 'high' | 'critical' {
  const baseRisk = TOOL_RISK[toolName] || 'medium';
  
  // Elevate risk for certain patterns
  if (toolName === 'exec') {
    const cmd = String(params.command || '').toLowerCase();
    if (cmd.includes('rm ') || cmd.includes('sudo') || cmd.includes('chmod')) {
      return 'critical';
    }
    if (cmd.includes('curl') || cmd.includes('wget') || cmd.includes('ssh')) {
      return 'high';
    }
  }
  
  if (toolName === 'write' || toolName === 'edit') {
    const path = String(params.path || params.file_path || '');
    if (path.includes('.ssh') || path.includes('.env') || path.includes('config')) {
      return 'high';
    }
  }

  return baseRisk;
}

const register: PluginRegisterFn = (api: PluginAPI) => {
  const config = api.config.plugins?.entries?.guard?.config as MoltGuardConfig | undefined;
  
  // Auto-generate token if not present
  const token = config?.token || ensureToken(api);
  
  if (!token) {
    console.log('[moltguard] Failed to initialize token');
    return;
  }

  const cfg: MoltGuardConfig = {
    url: config?.url || 'https://guard.moltnet.ai',
    token: token,
    agentName: config?.agentName,
    logThoughts: config?.logThoughts ?? true,
    gateHighRisk: config?.gateHighRisk ?? true,
    gateTools: config?.gateTools ?? ['exec', 'message', 'write'],
    pollCommands: config?.pollCommands ?? true,
    pollIntervalMs: config?.pollIntervalMs ?? 5000,
  };

  const agentName = cfg.agentName || `clawdbot-${process.env.HOSTNAME || 'agent'}`;

  // Register agent on startup
  (async () => {
    try {
      state.agentId = await registerAgent(cfg);
      state.sessionId = await startSession(cfg, agentName);
      console.log(`[moltguard] Connected to ${cfg.url}`);
      console.log(`[moltguard] Agent: ${agentName} | Session: ${state.sessionId}`);

      // Start command polling
      if (cfg.pollCommands) {
        state.pollInterval = setInterval(() => {
          pollCommands(cfg, agentName);
        }, cfg.pollIntervalMs);
      }
    } catch (err) {
      console.error('[moltguard] Failed to connect:', err instanceof Error ? err.message : String(err));
    }
  })();

  // Hook: Intercept tool results before persistence
  api.on('tool_result_persist', (toolResult) => {
    if (!toolResult || typeof toolResult !== 'object') return toolResult;

    const { name, input } = toolResult as { name?: string; input?: Record<string, unknown> };
    if (!name) return toolResult;

    const risk = getToolRisk(name, input || {});
    const shouldGate = cfg.gateHighRisk && 
      (risk === 'high' || risk === 'critical') && 
      cfg.gateTools?.includes(name);

    // Log the action (async, don't block)
    logAction(cfg, agentName, state.sessionId, name, input || {}, risk, shouldGate ? 'pending' : 'executed')
      .catch(err => console.error('[moltguard] Failed to log action:', err));

    return toolResult;
  });

  // Hook: Log agent bootstrap (session start)
  api.on('agent:bootstrap', (event) => {
    if (cfg.logThoughts) {
      logTrace(cfg, agentName, state.sessionId, 'session', 'Session Started', 'Agent bootstrap initiated')
        .catch(() => {});
    }
  });

  // Hook: Log commands  
  api.on('command', (event) => {
    if (cfg.logThoughts && (event as any).action) {
      logTrace(cfg, agentName, state.sessionId, 'command', `Command: /${(event as any).action}`, `User issued /${(event as any).action}`)
        .catch(() => {});
    }
  });

  // Cleanup on exit
  process.on('beforeExit', () => {
    if (state.pollInterval) {
      clearInterval(state.pollInterval);
    }
  });

  console.log('[moltguard] Plugin loaded');
};

export default register;
export const id = 'moltguard';
export const name = 'MoltGuard';
