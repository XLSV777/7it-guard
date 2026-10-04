#!/usr/bin/env node
// 7IT Guard fix playbook: a tiny local MCP server (stdio, Node built-ins only) with ONE tool,
// get_fix_playbook. It exists only so the optional fix key, which Claude Code keeps in the
// system's secure storage, can reach the one request that needs it: Claude Code hands the key
// to this process as GUARD_FIX_KEY and never puts it in the conversation.
//
// It does nothing on its own: no request at start-up, none in the background. When Claude calls
// the tool, and only if a key is set, it makes ONE request to https://7it.co.il/guard/playbook
// carrying the key, the ids of the findings (for example "csp_missing,no_dmarc") and the
// detected platform (for example "vercel,supabase"). Never the app's address, a report, code,
// files or the conversation. Without a key it makes no request at all.

import { createInterface } from 'node:readline';

const VERSION = '0.3.0';
const ENDPOINT = process.env.GUARD_PLAYBOOK_URL || 'https://7it.co.il/guard/playbook';
const REVIEW_URL = 'https://7it.co.il/services/ai-built-apps/';
const KNOWN_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const TOOL = {
  name: 'get_fix_playbook',
  title: 'Get the strict fix playbook',
  description: 'Use this after a 7IT Guard report, when the person asks to fix what it found and has set a 7IT key. Returns step-by-step fixes for the given finding ids, to the strict standard (OWASP ASVS level 2 references, deny-by-default database policies, a nonce-based Content Security Policy, HSTS preload, DMARC to p=reject). Sends only the key, the finding ids and the platform names. Call it once per report; it does not change any file.',
  inputSchema: {
    type: 'object',
    properties: {
      finding_ids: { type: 'array', items: { type: 'string', pattern: '^[a-z0-9_]{2,40}$' }, minItems: 1, maxItems: 60, description: 'The ids from the 7IT Guard report (the "id" of each finding in --json output), for example ["csp_missing","sb_table","no_dmarc"]' },
      stack: { type: 'array', items: { type: 'string', pattern: '^[a-z0-9-]{2,30}$' }, maxItems: 10, description: 'The "stack" list from the report, for example ["vercel","nextjs","supabase"]' },
    },
    required: ['finding_ids'],
  },
  annotations: { title: 'Get the strict fix playbook', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
};

const NO_KEY = [
  'No 7IT key is set, so no request was made.',
  'Every item in the 7IT Guard report already carries its fix, and the full report page has a copyable snippet for each one (header configs for Vercel, Netlify, Next.js and nginx, SPF and DMARC records, Supabase row level security policies). Fix them from there, one at a time, then run the check again.',
  `For the parts no outside check can see (load, scale, architecture, the logic behind the login), a senior review: ${REVIEW_URL}`,
].join('\n\n');

async function playbook(args) {
  const key = String(process.env.GUARD_FIX_KEY || '').trim();
  if (!key) return { content: [{ type: 'text', text: NO_KEY }] };
  const ids = (Array.isArray(args?.finding_ids) ? args.finding_ids : []).map(String).filter((s) => /^[a-z0-9_]{2,40}$/.test(s)).slice(0, 60);
  const stack = (Array.isArray(args?.stack) ? args.stack : []).map(String).filter((s) => /^[a-z0-9-]{2,30}$/.test(s)).slice(0, 10);
  if (!ids.length) return { isError: true, content: [{ type: 'text', text: 'Pass the finding ids from the 7IT Guard report.' }] };
  const url = `${ENDPOINT}?f=${encodeURIComponent(ids.join(','))}${stack.length ? `&s=${encodeURIComponent(stack.join(','))}` : ''}`;
  try {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${key}`, Accept: 'application/json', 'User-Agent': `7ITGuard/${VERSION}` }, signal: AbortSignal.timeout(20_000) });
    const j = await r.json().catch(() => null);
    if (r.ok && j?.playbook) return { content: [{ type: 'text', text: j.playbook }] };
    return { isError: true, content: [{ type: 'text', text: `${j?.message || `The playbook service answered HTTP ${r.status}.`}\n\nThe report itself still lists a fix for every item.` }] };
  } catch {
    return { isError: true, content: [{ type: 'text', text: 'The playbook service did not answer. The report itself still lists a fix for every item; try again later.' }] };
  }
}

// ---------------------------------------------------------------- MCP over stdio (JSON-RPC, one message per line)
const send = (msg) => process.stdout.write(JSON.stringify(msg) + '\n');
const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
const fail = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

async function handle(msg) {
  const { id, method, params } = msg;
  const isRequest = id !== undefined && id !== null;
  switch (method) {
    case 'initialize': {
      const asked = params?.protocolVersion;
      return reply(id, {
        protocolVersion: KNOWN_VERSIONS.includes(asked) ? asked : KNOWN_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'guard-fix', title: '7IT Guard fix playbook', version: VERSION },
        instructions: 'One tool, get_fix_playbook: call it once after a 7IT Guard report when the person wants the strict fix steps and has a 7IT key.',
      });
    }
    case 'ping':
      return isRequest && reply(id, {});
    case 'tools/list':
      return reply(id, { tools: [TOOL] });
    case 'tools/call':
      if (params?.name !== TOOL.name) return fail(id, -32602, `Unknown tool: ${params?.name}`);
      return reply(id, await playbook(params.arguments || {}));
    default:
      if (isRequest) return fail(id, -32601, `Method not found: ${method}`);
      return undefined; // notifications (initialized, cancelled) need no answer
  }
}

const rl = createInterface({ input: process.stdin });
rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return fail(null, -32700, 'Parse error'); }
  Promise.resolve(handle(msg)).catch((e) => msg.id != null && fail(msg.id, -32603, String(e?.message || e)));
});
rl.on('close', () => process.exit(0));
