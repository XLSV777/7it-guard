// Tests for scripts/check.mjs and scripts/fix-server.mjs. Run: node --test tests/check.test.mjs
// Nothing here touches the internet: every "https://<host>/..." request is routed to a local
// mock server by host name, DNS answers come from a stub, and the TLS check is stubbed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { inflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runCheck, textReport, reportLink, normalizeTarget, localToken, mailDomainOf, gradeOf, mapsKey, mapsHash } from '../scripts/check.mjs';

const here = dirname(fileURLToPath(import.meta.url));

// ------------------------------------------------------------------ the mock internet
function mockServer(routes) {
  const log = [];
  const server = http.createServer((req, res) => {
    const host = req.headers['x-mock-host'];
    const scheme = req.headers['x-mock-scheme'];
    const path = req.url;
    log.push({ host, scheme, method: req.method, path, headers: req.headers });
    const key = `${scheme === 'http' ? 'http://' : ''}${host}${path.split('?')[0]}`;
    const route = routes[key] || routes[`${host}*`];
    if (!route) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found'); return; }
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => route(req, res, body));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    const fetchImpl = (url, opts = {}) => {
      const u = new URL(url);
      const headers = { ...(opts.headers || {}), 'x-mock-host': u.hostname, 'x-mock-scheme': u.protocol.replace(':', '') };
      return fetch(`http://127.0.0.1:${port}${u.pathname}${u.search}`, { ...opts, headers });
    };
    resolve({ fetchImpl, log, close: () => new Promise((r) => server.close(r)), port });
  }));
}
const send = (status, headers, body = '') => (req, res) => { res.writeHead(status, headers); res.end(req.method === 'HEAD' ? undefined : body); };
const html = (body, headers = {}) => send(200, { 'content-type': 'text/html; charset=utf-8', ...headers }, body);

function dnsStub(records) {
  const notFound = () => Promise.reject(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));
  return {
    resolveTxt: (n) => (records.txt?.[n] ? Promise.resolve(records.txt[n].map((t) => [t])) : notFound()),
    resolveCname: (n) => (records.cname?.[n] ? Promise.resolve(records.cname[n]) : notFound()),
    resolveMx: (n) => (records.mx?.[n] ? Promise.resolve(records.mx[n]) : notFound()),
  };
}
const tlsOk = async () => ({ days: 80, valid: true, reason: '', issuer: 'Test CA' });
const jwt = (payload) => ['eyJhbGciOiJIUzI1NiJ9', Buffer.from(JSON.stringify(payload)).toString('base64url'), 'c2lnbmF0dXJlLXNpZ25hdHVyZQ'].join('.');

// A weak app: no security headers, plain HTTP still served, a public source map, accessibility
// and SEO gaps, no DMARC. Plus a Supabase backend and leaked files for the owner tests.
const WEAK = 'leaky-app.com';
const REF = 'abcdefghijklmnopqrst';
const ANON = jwt({ iss: 'supabase', ref: REF, role: 'anon' });
const FAKE_OPENAI = 'sk-proj-' + 'A1b2C3d4E5'.repeat(6);
function weakRoutes({ token = false } = {}) {
  const page = `<!doctype html><html><head><title>Leaky</title>${token ? `<meta name="7it-site-verification" content="${localToken(WEAK)}">` : ''}
    <script src="/assets/index-abc12345.js"></script></head><body><main><h1>Hi</h1>
    <img src="/a.png"><img src="/b.png" alt="b"><input type="email" placeholder="Email"><label for="n">Name</label><input id="n">
    <button><svg></svg></button><a href="/x"></a></main></body></html>`;
  return {
    [`${WEAK}/`]: html(page, { 'set-cookie': 'sid=abc; Path=/' }),
    [`http://${WEAK}/`]: html(page),
    [`${WEAK}/assets/index-abc12345.js`]: send(200, { 'content-type': 'application/javascript', 'cache-control': 'no-cache' }, `const u="https://${REF}.supabase.co";const k="${ANON}";const o="${FAKE_OPENAI}";`),
    [`${WEAK}/assets/index-abc12345.js.map`]: send(200, { 'content-type': 'application/json' }, '{"version":3,"sources":["a.ts"],"mappings":"AAAA"}'),
    [`${WEAK}/robots.txt`]: send(200, { 'content-type': 'text/plain' }, 'User-agent: *\nDisallow: /\n'),
    [`${WEAK}/.env`]: send(200, { 'content-type': 'text/plain' }, 'DATABASE_URL=postgres://secret\nAPI_KEY=xyz\n'),
    [`${WEAK}/7it-verify.txt`]: send(404, {}),
    [`${WEAK}*`]: html(page), // a single-page app answers every path with its home page
    [`${REF}.supabase.co/rest/v1/`]: send(200, { 'content-type': 'application/openapi+json' }, JSON.stringify({ paths: { '/': {}, '/profiles': {}, '/notes': {}, '/rpc/f': {} } })),
    [`${REF}.supabase.co/rest/v1/profiles`]: send(206, { 'content-range': '0-0/5' }),
    [`${REF}.supabase.co/rest/v1/notes`]: send(206, { 'content-range': '*/0' }),
    [`${REF}.supabase.co/auth/v1/settings`]: send(200, { 'content-type': 'application/json' }, '{"disable_signup":false}'),
    [`${REF}.supabase.co/storage/v1/bucket`]: send(200, { 'content-type': 'application/json' }, '[{"name":"avatars"},{"name":"private"}]'),
    [`${REF}.supabase.co/storage/v1/object/list/avatars`]: send(200, { 'content-type': 'application/json' }, '[{"name":"x.png"}]'),
    [`${REF}.supabase.co/storage/v1/object/list/private`]: send(200, { 'content-type': 'application/json' }, '[]'),
  };
}
const weakDns = dnsStub({ txt: { 'leaky-app.com': ['v=spf1 include:_spf.google.com ~all'] }, mx: { 'leaky-app.com': [{ exchange: 'mx.leaky-app.com', priority: 1 }] }, cname: { 'google._domainkey.leaky-app.com': ['dkim.example.net'] } });

// A strong app: every header, HTTPS redirect, clean HTML, robots, sitemap, enforced DMARC.
const STRONG = 'solid-app.com';
const STRONG_HEADERS = {
  'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()', 'cross-origin-opener-policy': 'same-origin', 'content-encoding': 'identity',
};
function strongRoutes() {
  const page = `<!doctype html><html lang="en"><head><title>Solid App: invoices for small teams</title><meta name="description" content="Send and track invoices for small teams, with reminders that go out on their own.">
    <link rel="canonical" href="https://${STRONG}/"><meta property="og:title" content="Solid"><meta property="og:image" content="https://${STRONG}/og.png">
    <script type="module" src="/assets/app-1a2b3c4d5e.js"></script></head><body><main><h1>Solid</h1><img src="/a.png" alt="A"><label>Email <input type="email"></label></main></body></html>`;
  return {
    [`${STRONG}/`]: html(page, STRONG_HEADERS),
    [`http://${STRONG}/`]: send(308, { location: `https://${STRONG}/` }),
    [`www.${STRONG}/`]: send(308, { location: `https://${STRONG}/` }),
    [`${STRONG}/assets/app-1a2b3c4d5e.js`]: send(200, { 'content-type': 'application/javascript', 'content-length': '2000', 'cache-control': 'public, max-age=31536000, immutable' }, 'console.log(1)'),
    [`${STRONG}/robots.txt`]: send(200, { 'content-type': 'text/plain' }, `User-agent: *\nAllow: /\nSitemap: https://${STRONG}/sitemap.xml\n`),
    [`${STRONG}/sitemap.xml`]: send(200, { 'content-type': 'application/xml' }, '<?xml version="1.0"?><urlset></urlset>'),
    [`${STRONG}/.well-known/security.txt`]: send(200, { 'content-type': 'text/plain' }, 'Contact: mailto:security@solid-app.com\n'),
  };
}
const strongDns = dnsStub({
  txt: { 'solid-app.com': ['v=spf1 include:_spf.google.com -all'], '_dmarc.solid-app.com': ['v=DMARC1; p=reject; rua=mailto:d@solid-app.com'] },
  mx: { 'solid-app.com': [{ exchange: 'mx.solid-app.com', priority: 1 }] },
  cname: { 'google._domainkey.solid-app.com': ['dkim.example.net'] },
});

const ids = (r) => r.findings.map((f) => f.id);

// ------------------------------------------------------------------ tests
test('addresses: public hosts only', () => {
  assert.equal(normalizeTarget('myapp.com').href, 'https://myapp.com/');
  assert.equal(normalizeTarget('http://myapp.com/x?y=1#z').href, 'https://myapp.com/x');
  for (const bad of ['localhost', '127.0.0.1', 'http://10.0.0.1', 'intranet', 'app.local', 'ftp://x.com', '']) assert.equal(normalizeTarget(bad), null, bad);
  assert.equal(mailDomainOf('app.example.co.uk'), 'example.co.uk');
  assert.equal(mailDomainOf('app.example.com'), 'example.com');
  assert.match(localToken('myapp.com'), /^7it-verify-[0-9a-f]{28}$/);
  assert.equal(localToken('myapp.com'), localToken('myapp.com'));
  assert.deepEqual(['A', 'B', 'C', 'D', 'F'], [95, 85, 75, 65, 10].map(gradeOf));
});

test('weak app, public checks: finds the gaps and never probes deep paths', async () => {
  const m = await mockServer(weakRoutes());
  try {
    const r = await runCheck(WEAK, { deps: { fetchImpl: m.fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
    for (const id of ['csp_missing', 'hsts_missing', 'frame_missing', 'http_no_redirect', 'sourcemap_public', 'cookie_insecure', 'img_alt', 'unlabeled_inputs', 'no_lang', 'robots_blocks_all', 'no_dmarc', 'soft_404', 'no_description', 'weak_caching'])
      assert.ok(ids(r).includes(id), `expected ${id}; got ${ids(r).join(',')}`);
    assert.ok(!ids(r).includes('no_dkim'), 'DKIM CNAME under the google selector counts');
    assert.equal(r.categories.data.score, null);
    assert.ok(r.score <= 69 && ['D', 'F'].includes(r.grade), `high findings cap the grade, got ${r.grade} ${r.score}`);
    assert.equal(r.ownership, 'not_requested');
    const paths = m.log.map((l) => l.path);
    for (const deep of ['/.env', '/.git/HEAD', '/7it-verify.txt']) assert.ok(!paths.includes(deep), `public mode must not request ${deep}`);
    assert.ok(!m.log.some((l) => /supabase/.test(l.host)), 'public mode must not touch the backend');
    assert.ok(!m.log.some((l) => l.path === '/assets/index-abc12345.js' && l.method === 'GET'), 'public mode must not download bundles to scan them');
    assert.deepEqual(r.mcp, [], 'a single-page app answering every path is not an MCP server');
    assert.ok(!m.log.some((l) => l.host === '7it.co.il'), 'no request to 7IT when the app publishes no MCP server');
    // Fix-before-shipping first, by severity.
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (let i = 1; i < r.findings.length; i++) assert.ok(order[r.findings[i - 1].sev] <= order[r.findings[i].sev]);
  } finally { await m.close(); }
});

test('owner flag without the token on the app: no deep checks', async () => {
  const m = await mockServer(weakRoutes());
  try {
    const r = await runCheck(WEAK, { owner: true, deps: { fetchImpl: m.fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
    assert.equal(r.ownership, 'token_missing');
    assert.ok(!m.log.some((l) => l.path === '/.env'));
    assert.ok(!m.log.some((l) => /supabase/.test(l.host)));
    assert.match(textReport(r, { link: false }), /ownership token is not on the app yet/);
  } finally { await m.close(); }
});

test('owner with the token: exposed files, secrets and Supabase, names and counts only', async () => {
  const m = await mockServer(weakRoutes({ token: true }));
  try {
    const r = await runCheck(WEAK, { owner: true, deps: { fetchImpl: m.fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
    assert.equal(r.ownership, 'verified_meta');
    const got = ids(r);
    for (const id of ['exposed_env', 'secret_openai', 'sb_table', 'sb_signup', 'sb_bucket']) assert.ok(got.includes(id), `expected ${id}; got ${got.join(',')}`);
    // .git/HEAD answers with the home page (single-page app): not a finding.
    assert.ok(!got.includes('exposed_git'));
    const table = r.findings.find((f) => f.id === 'sb_table');
    assert.equal(table.sev, 'critical');
    assert.match(table.title, /"profiles" \(5 rows\)/);
    assert.ok(!r.findings.some((f) => /notes/.test(f.title)), 'an empty or protected table is not reported');
    assert.deepEqual(r.tables, ['profiles']);
    assert.deepEqual(r.buckets, ['avatars']);
    assert.equal(r.grade, 'F');
    // Table checks are count-only HEAD requests; no row is ever requested.
    const tableCalls = m.log.filter((l) => /supabase/.test(l.host) && /^\/rest\/v1\/[a-z]/.test(l.path));
    assert.ok(tableCalls.length >= 2 && tableCalls.every((l) => l.method === 'HEAD'));
    // Bucket listing asks for one item at most.
    // No key value, file content or row anywhere in the output, the text or the link.
    const link = reportLink(r);
    const payload = inflateRawSync(Buffer.from(link.split('#r=')[1], 'base64url')).toString();
    for (const out of [JSON.stringify(r), textReport(r), payload]) {
      for (const secret of [FAKE_OPENAI, ANON, 'postgres://secret', 'x.png']) assert.ok(!out.includes(secret), `leaked ${secret.slice(0, 12)}`);
    }
  } finally { await m.close(); }
});

test('strong app: grade A, nothing to fix', async () => {
  const m = await mockServer(strongRoutes());
  try {
    const r = await runCheck(STRONG, { deps: { fetchImpl: m.fetchImpl, dns: strongDns, tls: tlsOk, env: {} } });
    const real = r.findings.filter((f) => f.sev !== 'info');
    assert.deepEqual(real.map((f) => f.id), [], `unexpected: ${real.map((f) => f.id).join(',')}`);
    assert.equal(r.grade, 'A');
    assert.equal(r.metrics.http_redirects_to_https, true);
    assert.equal(r.categories.email.score, 100);
  } finally { await m.close(); }
});

test('unreachable app and shared platform address', async () => {
  const fetchImpl = () => Promise.reject(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ENOTFOUND' } }));
  const r = await runCheck('gone-app.com', { deps: { fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
  assert.equal(r.error, 'unreachable');
  const m = await mockServer({ 'myapp.lovable.app/': html('<html lang="en"><head><title>My app on Lovable</title></head><body><main><h1>x</h1></main></body></html>') });
  try {
    const s = await runCheck('myapp.lovable.app', { deps: { fetchImpl: m.fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
    assert.equal(s.categories.email.score, null);
    assert.match(s.categories.email.note, /shared platform/);
  } finally { await m.close(); }
});

test('text report: order, link and the closing line', async () => {
  const m = await mockServer(weakRoutes());
  try {
    const r = await runCheck(WEAK, { deps: { fetchImpl: m.fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
    const t = textReport(r);
    assert.ok(t.indexOf('Fix before shipping') < t.indexOf('Fix soon'));
    assert.match(t, /nothing about the app sent to 7IT/);
    assert.match(t, /^7IT Guard \d+\.\d+\.\d+ · /);
    assert.match(t, /Full report: https:\/\/7it\.co\.il\/tools\/guard\/report\/#r=[A-Za-z0-9_-]+\n/);
    const last = t.trim().split('\n').pop();
    assert.match(last, /^Not checked from outside: load and traffic spikes, scale limits, architecture/);
    assert.match(last, /https:\/\/7it\.co\.il\/services\/ai-built-apps\/$/);
    assert.ok(!/\u2014/.test(t), 'no em dash');
    assert.ok(!/\bfree\b|\$\d|price|discount|offer/i.test(t), 'no prices or offers in the output');
    assert.match(t, new RegExp(localToken(WEAK)));
  } finally { await m.close(); }
});

test('report link: decodes, stays under 8 KB however long the report', () => {
  const base = { version: '0.2.0', host: 'big-app.com', checked_at: '2026-10-04T10:00:00.000Z', grade: 'F', score: 20, ownership: 'verified_meta', metrics: { ttfb_ms: 100 }, stack: ['vercel'], email_domain: 'big-app.com', tables: ['a'], buckets: [], categories: { security: { score: 10, note: '' } } };
  const findings = Array.from({ length: 300 }, (_, i) => ({ id: 'csp_missing', cat: 'security', sev: ['critical', 'high', 'medium', 'low', 'info'][i % 5], title: `Finding ${i} ${'x'.repeat(i % 50)} ${Math.random()}`, fix: `Fix ${i} ${Math.random()}` }));
  const link = reportLink({ ...base, findings });
  const enc = link.split('#r=')[1];
  assert.ok(enc.length <= 7800, `encoded ${enc.length}`);
  const p = JSON.parse(inflateRawSync(Buffer.from(enc, 'base64url')).toString());
  assert.equal(p.v, 1);
  assert.equal(p.h, 'big-app.com');
  assert.ok(p.f.length > 0 && p.f.every((f) => f[2] !== 'i'), 'drops the least severe items first');
  assert.ok(p.f.some((f) => f[2] === 'c'), 'keeps the critical items');
  assert.ok(p.x > 0, 'says how many were left out');
  const small = reportLink({ ...base, findings: findings.slice(0, 5) });
  assert.equal(JSON.parse(inflateRawSync(Buffer.from(small.split('#r=')[1], 'base64url')).toString()).f.length, 5);
});

// ------------------------------------------------------------------ an app that publishes an MCP server
const MCPAPP = 'agent-app.com';
function mcpRoutes({ listed }) {
  const page = '<!doctype html><html lang="en"><head><title>Agent App: tools for agents</title></head><body><main><h1>Agent</h1></main></body></html>';
  const key = mapsKey('https://' + MCPAPP + '/mcp');
  const h = mapsHash(key);
  return {
    [`${MCPAPP}/`]: html(page),
    [`${MCPAPP}/.well-known/mcp/server-card.json`]: send(200, { 'content-type': 'application/json' }, JSON.stringify({ name: 'x', remotes: [{ type: 'streamable-http', url: `https://${MCPAPP}/mcp` }] })),
    [`${MCPAPP}/mcp`]: send(401, { 'content-type': 'application/json', 'www-authenticate': `Bearer resource_metadata="https://${MCPAPP}/.well-known/oauth-protected-resource/mcp"` }, '{}'),
    // 7Maps' public list for the hash's first two characters; listed or not.
    [`7it.co.il/7maps/known/${h.slice(0, 2)}.json`]: send(200, { 'content-type': 'application/json' }, JSON.stringify({ v: 1, prefix: h.slice(0, 2), hashes: listed ? [h.slice(0, 2) + '0000000000', h] : [h.slice(0, 2) + '0000000000'] })),
  };
}

test('app with an MCP server: says whether it is on 7Maps without sending its address', async () => {
  assert.equal(mapsKey('https://WWW.Example.com:8443/mcp/'), 'example.com/mcp');
  assert.equal(mapsHash('example.com/mcp').length, 12);
  for (const listed of [true, false]) {
    const m = await mockServer(mcpRoutes({ listed }));
    try {
      const r = await runCheck(MCPAPP, { deps: { fetchImpl: m.fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
      assert.equal(r.mcp.length, 1);
      assert.equal(r.mcp[0].url, `https://${MCPAPP}/mcp`);
      assert.equal(r.mcp[0].on_7maps, listed);
      const toMaps = m.log.filter((l) => l.host === '7it.co.il');
      assert.equal(toMaps.length, 1, 'one download of one bucket');
      assert.match(toMaps[0].path, /^\/7maps\/known\/[0-9a-f]{2}\.json\?via=guard$/);
      for (const l of toMaps) assert.ok(!JSON.stringify(l).includes(MCPAPP), 'the address never goes to 7IT');
      const t = textReport(r);
      if (listed) {
        assert.ok(t.includes(`on 7Maps, the public map of MCP servers: https://7it.co.il/7maps/s/${MCPAPP}/mcp`));
        assert.ok(t.includes('verify ownership on 7Maps so agents see it is yours: https://7it.co.il/7maps/claim/'));
      } else assert.ok(t.includes('not on 7Maps yet. Its owner can add it: https://7it.co.il/7maps/submit/'));
      assert.ok(!/\bfree\b|\$\d|price|discount|offer/i.test(t), 'no prices or offers');
      const p = JSON.parse(inflateRawSync(Buffer.from(reportLink(r).split('#r=')[1], 'base64url')).toString());
      assert.deepEqual(p.mc, [[`https://${MCPAPP}/mcp`, listed ? 1 : 0]]);
    } finally { await m.close(); }
  }
  const m = await mockServer(mcpRoutes({ listed: true }));
  try {
    const r = await runCheck(MCPAPP, { maps: false, deps: { fetchImpl: m.fetchImpl, dns: weakDns, tls: tlsOk, env: {} } });
    assert.equal(r.mcp[0].on_7maps, null);
    assert.ok(!m.log.some((l) => l.host === '7it.co.il'), '--no-7maps makes no request to 7IT');
    assert.match(textReport(r), /not looked up on 7Maps in this run/);
  } finally { await m.close(); }
});

// ------------------------------------------------------------------ the fix playbook server
function rpc(env) {
  const child = spawn(process.execPath, [join(here, '..', 'scripts', 'fix-server.mjs')], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'inherit'] });
  let buf = '';
  const waiting = new Map();
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, i); buf = buf.slice(i + 1); const msg = JSON.parse(line); waiting.get(msg.id)?.(msg); }
  });
  let id = 0;
  const call = (method, params) => new Promise((resolve) => { const n = ++id; waiting.set(n, resolve); child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: n, method, params }) + '\n'); });
  return { call, close: () => child.kill() };
}

test('fix server: no key means no request; with a key it sends only key, ids and stack', async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, auth: req.headers.authorization });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ playbook: '# Strict playbook\n1. CSP with nonces' }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/guard/playbook`;
  try {
    const a = rpc({ GUARD_FIX_KEY: '', GUARD_PLAYBOOK_URL: url });
    const init = await a.call('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    assert.equal(init.result.protocolVersion, '2025-06-18');
    const list = await a.call('tools/list', {});
    assert.deepEqual(list.result.tools.map((t) => t.name), ['get_fix_playbook']);
    assert.equal(list.result.tools[0].annotations.readOnlyHint, true);
    const none = await a.call('tools/call', { name: 'get_fix_playbook', arguments: { finding_ids: ['csp_missing'] } });
    assert.match(none.result.content[0].text, /No 7IT key is set, so no request was made/);
    assert.ok(!/\$\d|price|\bfree\b/i.test(none.result.content[0].text));
    a.close();
    assert.equal(seen.length, 0);

    const b = rpc({ GUARD_FIX_KEY: 'test-key-123', GUARD_PLAYBOOK_URL: url });
    await b.call('initialize', { protocolVersion: '2099-01-01', capabilities: {}, clientInfo: { name: 't', version: '1' } });
    const got = await b.call('tools/call', { name: 'get_fix_playbook', arguments: { finding_ids: ['csp_missing', 'no_dmarc', 'BAD ID'], stack: ['vercel'] } });
    assert.match(got.result.content[0].text, /Strict playbook/);
    b.close();
    assert.equal(seen.length, 1);
    assert.equal(seen[0].auth, 'Bearer test-key-123');
    assert.equal(decodeURIComponent(seen[0].url), '/guard/playbook?f=csp_missing,no_dmarc&s=vercel');
  } finally { await new Promise((r) => server.close(r)); }
});
