// The session helpers' check (scripts/session/lib.mjs, 0.6.0): the deploy check and /7it-guard:recheck run the plugin's
// own check on this machine, and a finding counts as fixed only when its part ran this time.
//   node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { localToken } from '../skills/guard/scripts/check.mjs';
import { brandBlock, compareRuns, isDeep, localCheck, runOf, statusOf } from '../scripts/session/lib.mjs';

const f = (id, cat, sev, title = id) => ({ id, cat, sev, title, fix: 'Fix it.' });
const run = (findings, { deep = true, ran = {} } = {}) => runOf({
  findings,
  ownership: deep ? 'verified_meta' : 'token_missing',
  categories: Object.fromEntries(['security', 'data', 'secrets', 'email', 'performance', 'accessibility', 'seo', 'reliability'].map((k) => [k, { score: ran[k] === false ? null : 100 }])),
  token: '7it-verify-x',
}, 'myapp.com', 1);

test('U2: a leaked Supabase key is never "fixed" when the deep part did not run', () => {
  const before = run([f('secret_sb_service', 'secrets', 'critical', 'A Supabase service role key is in the code sent to browsers.'), f('csp_missing', 'security', 'medium')]);
  const now = run([], { deep: false });
  const c = compareRuns(before, now);
  assert.deepEqual(c.gone.map((x) => x.id), ['csp_missing'], 'the public finding whose part ran is gone');
  assert.deepEqual(c.unchecked.map((x) => x.id), ['secret_sb_service'], 'the deep finding is listed as not checked');
  assert.equal(statusOf(now, c.unchecked), 'NOT VERIFIED', 'never PASS while a critical finding went unchecked');
  assert.match(brandBlock('myapp.com', now, c.unchecked), /^7IT Guard · NOT VERIFIED · myapp\.com/);
});

test('a part that did not run this time keeps its findings out of "gone"', () => {
  const before = run([f('no_dmarc', 'email', 'high'), f('no_title', 'seo', 'medium')]);
  const now = run([], { ran: { email: false } });
  const c = compareRuns(before, now);
  assert.deepEqual(c.unchecked.map((x) => x.id), ['no_dmarc']);
  assert.deepEqual(c.gone.map((x) => x.id), ['no_title']);
  assert.equal(statusOf(now, c.unchecked), 'NOT VERIFIED');
});

test('everything ran: gone, still, new, and the four answers', () => {
  const before = run([f('exposed_env', 'data', 'critical'), f('hsts_missing', 'security', 'medium')]);
  const now = run([f('hsts_missing', 'security', 'medium'), f('noindex', 'seo', 'high')]);
  const c = compareRuns(before, now);
  assert.deepEqual([c.gone, c.still, c.added, c.unchecked].map((xs) => xs.map((x) => x.id)), [['exposed_env'], ['hsts_missing'], ['noindex'], []]);
  assert.equal(statusOf(now, c.unchecked), 'PROBLEM');
  assert.equal(statusOf(run([f('hsts_missing', 'security', 'medium')])), 'NEEDS A LOOK');
  assert.equal(statusOf(run([f('no_canonical', 'seo', 'low')])), 'PASS', 'low findings do not block PASS');
  assert.equal(statusOf(run([])), 'PASS');
  assert.equal(statusOf(run([], { deep: false })), 'NOT VERIFIED', 'no PASS without the deep part');
});

test('findings are keyed by id, not by their changing titles', () => {
  const before = run([f('sourcemap_public', 'secrets', 'high', 'A JavaScript source map is public (/assets/index-4f2a.js.map).')]);
  const now = run([f('sourcemap_public', 'secrets', 'high', 'A JavaScript source map is public (/assets/index-9bc1.js.map).')]);
  const c = compareRuns(before, now);
  assert.deepEqual([c.gone.length, c.still.length, c.added.length], [0, 1, 0], 'a new build hash is the same open finding');
  const two = run([f('exposed_env', 'data', 'critical', 'a'), f('exposed_env', 'data', 'critical', 'b')]);
  assert.deepEqual(two.findings.map((x) => x.k), ['exposed_env', 'exposed_env#2']);
  assert.ok(isDeep({ id: 'secret_openai', cat: 'secrets' }) && !isDeep({ id: 'sourcemap_public', cat: 'secrets' }) && isDeep({ id: 'sb_advisor', cat: 'data' }));
});

test('a run saved by an earlier version (the server shape) is a baseline, not compared', () => {
  const c = compareRuns({ at: 1, site: 'myapp.com', findings: [{ k: 'security|x', sev: 'high', area: 'security', title: 'x' }] }, run([]));
  assert.equal(c.baseline, true);
  assert.deepEqual(c.gone, []);
});

test('localCheck runs the plugin check on this machine, with the deep part when the token is on the app', async () => {
  const HOST = 'owned-app.com';
  const log = [];
  const page = (withToken) => `<!doctype html><html lang="en"><head><title>Owned app for the session test</title>${withToken ? `<meta name="7it-site-verification" content="${localToken(HOST)}">` : ''}</head><body><main><h1>Hi</h1></main></body></html>`;
  let leak = true;
  const server = http.createServer((req, res) => {
    const host = req.headers['x-mock-host'];
    log.push({ host, path: req.url });
    if (host !== HOST) { res.writeHead(404); res.end(); return; }
    if (req.url === '/.env' && leak) { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('DATABASE_URL=postgres://secret\nAPI_KEY=xyz\n'); return; }
    if (req.url === '/' || req.url === '/index.html') { res.writeHead(200, { 'content-type': 'text/html' }); res.end(page(true)); return; }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const fetchImpl = (url, opts = {}) => { const u = new URL(url); return fetch(`http://127.0.0.1:${port}${u.pathname}${u.search}`, { ...opts, headers: { ...(opts.headers || {}), 'x-mock-host': u.hostname } }); };
  const deps = { fetchImpl, dns: { resolveTxt: () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })), resolveCname: () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })), resolveMx: () => Promise.reject(Object.assign(new Error('x'), { code: 'ENOTFOUND' })) }, tls: async () => ({ days: 80, valid: true, reason: '', issuer: 'Test CA' }) };
  try {
    const a = await localCheck(HOST, { owner: true, deps });
    const first = runOf(a.report, HOST, 1);
    assert.equal(first.deep, true, 'the token is on the app, so the deep part ran');
    assert.ok(first.findings.some((x) => x.id === 'exposed_env'), 'the exposed .env is found');
    assert.equal(statusOf(first), 'PROBLEM');
    assert.ok(a.link.startsWith('https://7it.co.il/tools/guard/report/#r='));
    leak = false;
    const b = await localCheck(HOST, { owner: true, deps });
    const second = runOf(b.report, HOST, 2);
    const c = compareRuns(first, second);
    assert.ok(c.gone.some((x) => x.id === 'exposed_env'), 'the fixed file is gone, verified');
    assert.ok(!log.some((l) => l.host === '7it.co.il'), 'no request to 7IT');
    assert.ok(!JSON.stringify(second).includes('postgres://secret'), 'no file content kept');
  } finally { await new Promise((r) => server.close(r)); }
});
