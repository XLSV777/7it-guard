// 7IT Guard Vault: the helper that runs on the customer's GitHub runner (V1, 2026-10-08; docs/features/backup-vault.md).
// The workflow generator (scripts/vault/workflow.mjs) copies this file, byte for byte, into the customer's own workflow file
// (a heredoc written to $RUNNER_TEMP), so every line that runs is visible in the customer's repository (Lior's decision 1 of
// 2026-10-08: no shared action, no public repo, nothing fetched from 7IT at run time). The same file is imported by the local
// tests (scripts/guard-vault-local.mts), so what is tested is what ships.
//
// Rules: Node built-ins only; never prints a secret, a host name, a table name or a file name; the receipt is built from an
// allowlist of fields (buildReceipt) and is the only thing that ever leaves the runner for 7IT.
//
// Commands (node vault.mjs <command>; inputs through environment variables set by the workflow):
//   classify <file>     reads pg_dump's error output, prints one error code (auth, network, version, dump)
//   db-stats            sha256 and size of the plaintext dump + the table and row counts -> $T/db.json
//   db-check            compares the restored database's counts with the copy's db.json -> $T/db-check.json
//   files-backup        new and changed storage files, each encrypted to the recipients -> $T/files.json
//   files-restore       a date's files: verify a sample (check) or copy all to the restore remote -> $T/files-restore.json
//   resolve-date        picks the date to restore (latest or YYYY-MM-DD) for the mode -> $GITHUB_OUTPUT
//   prune               retention: keeps the restorable dates, removes the rest -> $T/dates.json
//   receipt             builds the receipt and posts it with the run's GitHub identity token
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, createReadStream, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const RUNNER_VERSION = 1;
export const RECEIPT_AUDIENCE = '7it-guard-vault';
export const RECEIPT_MAX_BYTES = 6144;
export const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
export const STAMP_RE = /^\d{8}T\d{6}Z$/;
export const ERROR_CODES = ['auth', 'network', 'version', 'dump', 'encrypt', 'upload', 'files', 'prune', 'config', 'download', 'decrypt', 'restore', 'check', 'receipt', 'unknown'];
export const REMOTE_KINDS = ['r2', 's3', 'b2', 'drive', 'gcs', 'other'];
export const FILES_STATES = ['ok', 'none', 'partial', 'failed'];
export const PART_RESULTS = ['pass', 'fail', 'skip'];
export const RESTORE_MODES = ['full', 'database', 'files'];
export const RESTORE_TARGETS = ['check', 'new'];

// ---------------------------------------------------------------- small pure helpers (tested)
const isInt = (v) => Number.isSafeInteger(v) && v >= 0;
const isIso = (v) => typeof v === 'string' && v.length <= 30 && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(v) && Number.isFinite(Date.parse(v));
const isHex64 = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const pick = (v, list) => (list.includes(v) ? v : undefined);

// pg_dump's error text -> one code. The text itself never leaves the runner.
export function classifyDumpError(text) {
  const t = String(text || '');
  if (/password authentication failed|no pg_hba\.conf entry|role "[^"]*" does not exist|authentication failed|SASL|Tenant or user not found/i.test(t)) return 'auth';
  if (/server version mismatch|aborting because of server version/i.test(t)) return 'version';
  if (/could not translate host|Network is unreachable|could not connect|Connection refused|timeout expired|Connection timed out|No route to host|Cannot assign requested address/i.test(t)) return 'network';
  return 'dump';
}

// The restorable dates: the newest `d` dates, the newest date of each of the newest `w` ISO weeks and of each of the newest
// `m` months. The newest date is always kept. Dates are YYYY-MM-DD strings; anything else is ignored (and never deleted).
export function isoWeek(day) {
  const t = new Date(day + 'T00:00:00Z'), dow = (t.getUTCDay() + 6) % 7;
  t.setUTCDate(t.getUTCDate() - dow + 3);
  const y = t.getUTCFullYear(), first = new Date(Date.UTC(y, 0, 4));
  const w = 1 + Math.round(((t - first) / 86400000 - 3 + ((first.getUTCDay() + 6) % 7)) / 7);
  return `${y}-W${String(w).padStart(2, '0')}`;
}
export function keepDates(dates, keep) {
  const all = [...new Set(dates.filter((d) => DATE_RE.test(d)))].sort().reverse();
  const out = new Set(all.slice(0, Math.max(1, keep.daily | 0)));
  const byGroup = (key, n) => { const seen = new Set(); for (const d of all) { const g = key(d); if (seen.has(g)) continue; if (seen.size >= n) break; seen.add(g); out.add(d); } };
  byGroup(isoWeek, keep.weekly | 0);
  byGroup((d) => d.slice(0, 7), keep.monthly | 0);
  return [...out].sort();
}

// What each kept date holds: 'b' both, 'd' the database only, 'f' files only.
export function datesMap(dbDates, fileDates, kept) {
  const db = new Set(dbDates), fl = new Set(fileDates), out = {};
  for (const d of kept) { const a = db.has(d), b = fl.has(d); if (a || b) out[d] = a && b ? 'b' : a ? 'd' : 'f'; }
  return out;
}

// A storage file's id: a hash of where it is, its size and its provider checksum (or time). Nothing readable.
export function objectId(o) {
  return createHash('sha256').update(`7it-vault|${o.Path}|${o.Size}|${(o.Hashes && (o.Hashes.md5 || o.Hashes.sha1)) || o.ModTime || ''}`).digest('hex').slice(0, 40);
}
// The plan of one files run: which listed files are already stored (by id, with the run stamp of the manifest that holds them)
// and which must be uploaded, inside the run's limits (the rest waits for the next night: state 'partial').
export function filesPlan(listing, stored, prevRefs, limits) {
  const files = listing.filter((o) => o && !o.IsDir && typeof o.Path === 'string' && isInt(o.Size));
  const keep = [], upload = [];
  let newBytes = 0, cut = false;
  for (const o of files) {
    const id = objectId(o), origin = prevRefs.get(id);
    if (origin && stored.has(id)) { keep.push({ id, origin, size: o.Size }); continue; }
    if (upload.length >= limits.maxNew || newBytes + o.Size > limits.maxBytes) { cut = true; continue; }
    upload.push({ id, o }); newBytes += o.Size;
  }
  return { files: files.length, bytes: files.reduce((a, o) => a + o.Size, 0), keep, upload, newBytes, cut };
}
export const parseRefs = (text) => {
  const m = new Map();
  for (const line of String(text || '').split('\n')) { const [id, st] = line.trim().split(' '); if (/^[0-9a-f]{40}$/.test(id || '') && STAMP_RE.test(st || '')) m.set(id, st); }
  return m;
};
export const refsText = (entries) => entries.map((e) => `${e.id} ${e.origin}`).join('\n') + '\n';
// Objects no kept date refers to (safe to delete), and manifests no kept date needs.
export function pruneSets(keptRefs, storedObjects, storedManifests) {
  const ids = new Set(), stamps = new Set();
  for (const refs of keptRefs) for (const [id, st] of refs) { ids.add(id); stamps.add(st); }
  return { objects: [...storedObjects].filter((id) => !ids.has(id)), manifests: [...storedManifests].filter((st) => !stamps.has(st)) };
}
// The restored database's counts against the copy's. Tables must all be there; rows may differ from the planner's estimate
// taken at dump time, so only a large gap on a table set with real data fails.
export function dbCheck(src, got) {
  if (!src || !got || !isInt(src.tables) || !isInt(got.tables)) return { ok: false, why: 'counts' };
  if (got.tables < src.tables) return { ok: false, why: 'tables' };
  if (isInt(src.rows) && src.rows >= 1000 && isInt(got.rows) && got.rows < src.rows * 0.5) return { ok: false, why: 'rows' };
  return { ok: true };
}
// A spread sample of n entries (deterministic: the same date always checks the same files).
export function sampleOf(list, n) {
  if (list.length <= n) return list.slice();
  const out = [], step = list.length / n;
  for (let i = 0; i < n; i++) out.push(list[Math.floor(i * step)]);
  return out;
}
export function pickDate(want, dbDates, fileDates, mode, filesOn) {
  const db = new Set(dbDates), fl = new Set(fileDates);
  const fits = (d) => (mode === 'database' ? db.has(d) : mode === 'files' ? fl.has(d) : db.has(d) && (!filesOn || fl.has(d)));
  if (want && want !== 'latest') return DATE_RE.test(want) && fits(want) ? want : null;
  return [...new Set([...dbDates, ...fileDates])].filter((d) => DATE_RE.test(d)).sort().reverse().find(fits) || null;
}

// ---------------------------------------------------------------- the receipt (the allowlist; the only data sent to 7IT)
// Every field is checked by type and range; anything not listed here is dropped, whatever the input holds. The server
// (api/_guardvault.ts cleanReceipt) refuses a body with any other field, so the two lists are tested together.
export const RECEIPT_FIELDS = ['v', 'kind', 'wf', 'ok', 'started', 'finished', 'engine', 'pg', 'remote', 'err', 'db', 'files', 'dates', 'keep', 'restore'];
export function buildReceipt(x) {
  const r = { v: 1, kind: pick(x.kind, ['backup', 'restore']) || 'backup', wf: isInt(x.wf) ? x.wf : 0, ok: x.ok === true };
  if (isIso(x.started)) r.started = x.started;
  if (isIso(x.finished)) r.finished = x.finished;
  r.engine = 'postgres';
  if (isInt(x.pg) && x.pg >= 9 && x.pg <= 30) r.pg = x.pg;
  r.remote = pick(x.remote, REMOTE_KINDS) || 'other';
  const err = pick(x.err, ERROR_CODES);
  if (!r.ok) r.err = err || 'unknown';
  const db = x.db;
  if (db && isInt(db.bytes) && isHex64(db.sha256)) r.db = { bytes: db.bytes, sha256: db.sha256, tables: isInt(db.tables) ? db.tables : 0, rows: isInt(db.rows) ? db.rows : 0 };
  const f = x.files;
  if (f && pick(f.st, FILES_STATES)) r.files = f.st === 'none' ? { st: 'none' } : { st: f.st, n: isInt(f.n) ? f.n : 0, bytes: isInt(f.bytes) ? f.bytes : 0, new_n: isInt(f.new_n) ? f.new_n : 0, new_bytes: isInt(f.new_bytes) ? f.new_bytes : 0 };
  if (x.dates && typeof x.dates === 'object') {
    const d = Object.entries(x.dates).filter(([k, v]) => DATE_RE.test(k) && ['b', 'd', 'f'].includes(v)).sort((a, b) => (a[0] < b[0] ? 1 : -1)).slice(0, 60);
    if (d.length) r.dates = Object.fromEntries(d);
  }
  const k = x.keep;
  if (k && isInt(k.d) && isInt(k.w) && isInt(k.m) && k.d <= 400 && k.w <= 260 && k.m <= 120) r.keep = { d: k.d, w: k.w, m: k.m };
  const rs = x.restore;
  if (r.kind === 'restore' && rs && pick(rs.mode, RESTORE_MODES) && pick(rs.target, RESTORE_TARGETS)) {
    r.restore = { mode: rs.mode, target: rs.target, ...(DATE_RE.test(rs.date || '') ? { date: rs.date } : {}), db: pick(rs.db, PART_RESULTS) || 'skip', files: pick(rs.files, PART_RESULTS) || 'skip', sample: isInt(rs.sample) ? Math.min(rs.sample, 100000) : 0, errors: isInt(rs.errors) ? Math.min(rs.errors, 100000) : 0 };
  }
  return r;
}

// ---------------------------------------------------------------- process helpers (runner only)
const env = (k, d = '') => (process.env[k] === undefined ? d : String(process.env[k]));
const T = () => env('T') || env('RUNNER_TEMP', '/tmp');
const readJson = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return null; } };
const writeJson = (name, v) => writeFileSync(join(T(), name), JSON.stringify(v));
function run(cmd, args, opts = {}) {
  return new Promise((res) => {
    const p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opts });
    const out = [], err = [];
    p.stdout.on('data', (c) => out.push(c)); p.stderr.on('data', (c) => err.push(c));
    p.on('error', () => res({ code: 127, out: '', err: 'spawn' }));
    p.on('close', (code) => res({ code, out: Buffer.concat(out).toString('utf8'), err: Buffer.concat(err).toString('utf8') }));
  });
}
const RC = ['--retries', '3', '--low-level-retries', '10', '-q'];
const rclone = (...a) => run('rclone', [...a, ...RC]);
async function lsf(path, dirs) { const r = await rclone('lsf', ...(dirs ? ['--dirs-only'] : ['--files-only']), path); return r.code === 0 ? r.out.split('\n').map((s) => s.replace(/\/$/, '').trim()).filter(Boolean) : null; }
const recipients = () => env('VAULT_RECIPIENTS').split(/\s+/).filter((r) => /^age1[02-9ac-hj-np-z]{58}$/.test(r));
// One stream: source -> sha256 -> (age) -> destination. Resolves with the plaintext hash and size, or null on any failure.
function pipeline(srcArgs, midArgs, dstArgs, hashWhere) {
  return new Promise((res) => {
    const a = spawn('rclone', [...srcArgs, ...RC], { stdio: ['ignore', 'pipe', 'ignore'] });
    const m = spawn('age', midArgs, { stdio: ['pipe', 'pipe', 'ignore'] });
    const b = spawn(dstArgs[0], dstArgs.slice(1), { stdio: ['pipe', 'ignore', 'ignore'] });
    const h = createHash('sha256'); let n = 0, left = 3, bad = false;
    const done = (code) => { if (code !== 0) bad = true; if (--left === 0) res(bad ? null : { sha: h.digest('hex'), bytes: n }); };
    for (const p of [a, m, b]) { p.on('error', () => { bad = true; }); p.on('close', done); }
    const tap = hashWhere === 'in' ? a.stdout : m.stdout;
    tap.on('data', (c) => { h.update(c); n += c.length; });
    a.stdout.pipe(m.stdin); m.stdout.pipe(b.stdin);
    m.stdin.on('error', () => { bad = true; }); b.stdin.on('error', () => { bad = true; });
  });
}
async function pool(items, n, fn) { let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const x = items[i++]; await fn(x); } })); }
const nowStamp = () => new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
const output = (k, v) => { const f = env('GITHUB_OUTPUT'); if (f) appendFileSync(f, `${k}=${v}\n`); else console.log(`${k}=${v}`); };

// ---------------------------------------------------------------- commands
async function sha256File(p) { return new Promise((res, rej) => { const h = createHash('sha256'); let n = 0; createReadStream(p).on('data', (c) => { h.update(c); n += c.length; }).on('end', () => res({ sha: h.digest('hex'), bytes: n })).on('error', rej); }); }
function counts(text) { const [t, r] = String(text || '').trim().split('|').map((x) => Number(x)); return { tables: isInt(t) ? t : 0, rows: isInt(Math.round(r)) ? Math.round(r) : 0 }; }

const commands = {
  classify: async (file) => { console.log(classifyDumpError(existsSync(file) ? readFileSync(file, 'utf8') : '')); },
  'db-stats': async () => {
    const s = await sha256File(join(T(), 'db.dump')), c = counts(env('VAULT_COUNTS'));
    writeJson('db.json', { bytes: s.bytes, sha256: s.sha, tables: c.tables, rows: c.rows, pg: Number(env('VAULT_PG')) || 0 });
  },
  'db-check': async () => {
    const src = readJson(join(T(), 'db.json')), r = dbCheck(src, counts(env('VAULT_COUNTS')));
    let errors = 0; try { errors = (readFileSync(join(T(), 'restore.err'), 'utf8').match(/^pg_restore: error:/gm) || []).length; } catch { /* none */ }
    writeJson('db-check.json', { ok: r.ok, errors });
    if (!r.ok) { console.log('The restored database does not match the copy (' + r.why + ').'); process.exit(1); }
  },
  'files-backup': async () => {
    const R = env('VAULT_REMOTE'), src = env('VAULT_FILES_SRC'), rec = recipients(), stamp = nowStamp(), today = stamp.slice(0, 4) + '-' + stamp.slice(4, 6) + '-' + stamp.slice(6, 8);
    if (!src) { writeJson('files.json', { st: 'none' }); return; }
    const fail = (why) => { writeJson('files.json', { st: 'failed' }); console.log('Files: ' + why); process.exit(1); };
    if (rec.length < 1) fail('no recipient');
    const ls = await run('rclone', ['lsjson', '-R', '--files-only', '--hash', '--no-mimetype', src, ...RC], { maxBuffer: 1 << 30 });
    if (ls.code !== 0) fail('the storage could not be listed');
    let listing; try { listing = JSON.parse(ls.out || '[]'); } catch { fail('the listing could not be read'); }
    if (!listing.length) { writeJson('files.json', { st: 'none' }); return; }
    const stored = new Set(((await lsf(R + '/files/objects/')) || []).map((f) => f.replace(/\.age$/, '')));
    const refDates = ((await lsf(R + '/files/refs/')) || []).map((f) => f.replace(/\.txt$/, '')).filter((d) => DATE_RE.test(d)).sort();
    const last = refDates[refDates.length - 1];
    const prev = last ? parseRefs((await rclone('cat', `${R}/files/refs/${last}.txt`)).out) : new Map();
    const plan = filesPlan(listing, stored, prev, { maxNew: Number(env('VAULT_FILES_MAX_NEW', '20000')) || 20000, maxBytes: Number(env('VAULT_FILES_MAX_BYTES', String(10 * 2 ** 30))) || 10 * 2 ** 30 });
    const manifest = [], refs = [...plan.keep];
    let failed = 0;
    await pool(plan.upload, 4, async ({ id, o }) => {
      const r = await pipeline(['cat', `${src}${o.Path}`], rec.flatMap((x) => ['-r', x]), ['rclone', 'rcat', `${R}/files/objects/${id}.age`, ...RC], 'in');
      if (!r) { failed++; return; }
      manifest.push({ p: o.Path, s: r.bytes, h: r.sha, id }); refs.push({ id, origin: stamp, size: r.bytes });
    });
    if (manifest.length) {
      writeFileSync(join(T(), 'manifest.json'), JSON.stringify({ v: 1, stamp, files: manifest }));
      const enc = await run('age', [...rec.flatMap((x) => ['-r', x]), '-o', join(T(), 'manifest.json.age'), join(T(), 'manifest.json')]);
      const up = enc.code === 0 ? await rclone('copyto', join(T(), 'manifest.json.age'), `${R}/files/manifests/${stamp}.json.age`) : enc;
      if (up.code !== 0) fail('the list of files could not be stored');
    }
    writeFileSync(join(T(), 'refs.txt'), refsText(refs));
    if ((await rclone('copyto', join(T(), 'refs.txt'), `${R}/files/refs/${today}.txt`)).code !== 0) fail('the date index could not be stored');
    const st = failed ? 'failed' : plan.cut ? 'partial' : 'ok';
    writeJson('files.json', { st, n: plan.files, bytes: plan.bytes, new_n: manifest.length, new_bytes: manifest.reduce((a, m) => a + m.s, 0) });
    if (failed) { console.log(`Files: ${failed} could not be copied.`); process.exit(1); }
  },
  'files-restore': async () => {
    const R = env('VAULT_REMOTE'), date = env('VAULT_DATE'), key = env('VAULT_KEY_FILE'), mode = env('VAULT_TARGET') === 'new' ? 'copy' : 'verify';
    const out = (o) => writeJson('files-restore.json', o);
    const refs = parseRefs((await rclone('cat', `${R}/files/refs/${date}.txt`)).out);
    if (!refs.size) { out({ result: 'fail', sample: 0 }); console.log('Files: nothing stored for that date.'); process.exit(1); }
    const byStamp = new Map();
    for (const st of new Set(refs.values())) {
      const dec = await run('sh', ['-c', 'rclone cat "$1" -q | age -d -i "$2"', 'sh', `${R}/files/manifests/${st}.json.age`, key], { maxBuffer: 1 << 30 });
      let m = null; try { m = JSON.parse(dec.out); } catch { /* bad */ }
      if (!m || !Array.isArray(m.files)) { out({ result: 'fail', sample: 0 }); console.log('Files: a list of files could not be opened.'); process.exit(1); }
      for (const f of m.files) byStamp.set(f.id, f);
    }
    const entries = [...refs.keys()].map((id) => byStamp.get(id)).filter(Boolean);
    const todo = mode === 'copy' ? entries : sampleOf(entries, Number(env('VAULT_SAMPLE', '20')) || 20);
    let bad = entries.length < refs.size ? refs.size - entries.length : 0;
    const dst = env('VAULT_RESTORE_FILES', 'restore-files:');
    await pool(todo, 4, async (f) => {
      const r = await pipeline(['cat', `${R}/files/objects/${f.id}.age`], ['-d', '-i', key], mode === 'copy' ? ['rclone', 'rcat', `${dst}${f.p}`, ...RC] : ['sh', '-c', 'cat > /dev/null'], 'out');
      if (!r || r.sha !== f.h) bad++;
    });
    out({ result: bad ? 'fail' : 'pass', sample: todo.length });
    if (bad) { console.log(`Files: ${bad} did not match their checksum.`); process.exit(1); }
  },
  'resolve-date': async () => {
    const R = env('VAULT_REMOTE'), mode = RESTORE_MODES.includes(env('VAULT_MODE')) ? env('VAULT_MODE') : 'full', filesOn = env('VAULT_FILES_ON') === '1';
    const want = env('VAULT_WANT', 'latest').trim() || 'latest';
    if (want !== 'latest' && !DATE_RE.test(want)) { console.log('The date must look like 2026-10-08, or be latest.'); process.exit(1); }
    const db = ((await lsf(R + '/db/', true)) || []).filter((d) => DATE_RE.test(d));
    const fl = filesOn ? ((await lsf(R + '/files/refs/')) || []).map((f) => f.replace(/\.txt$/, '')).filter((d) => DATE_RE.test(d)) : [];
    const d = pickDate(want, db, fl, mode, filesOn);
    if (!d) { console.log(`No backup holds what this restore needs (${mode}) for ${want}.`); process.exit(1); }
    output('date', d); output('db', mode !== 'files' ? '1' : '0'); output('files', filesOn && mode !== 'database' ? '1' : '0');
  },
  prune: async () => {
    const R = env('VAULT_REMOTE'), keep = { daily: Number(env('VAULT_KEEP_D', '14')), weekly: Number(env('VAULT_KEEP_W', '8')), monthly: Number(env('VAULT_KEEP_M', '12')) };
    const db = ((await lsf(R + '/db/', true)) || []).filter((d) => DATE_RE.test(d));
    const refFiles = ((await lsf(R + '/files/refs/')) || []).map((f) => f.replace(/\.txt$/, '')).filter((d) => DATE_RE.test(d));
    const kept = keepDates([...db, ...refFiles], keep);
    // Safety: nothing is removed unless today's copy is among the kept dates.
    const today = new Date().toISOString().slice(0, 10);
    if (!kept.includes(today)) { writeJson('dates.json', datesMap(db, refFiles, kept)); console.log('Retention skipped: no copy for today.'); return; }
    for (const d of db) if (!kept.includes(d)) await rclone('purge', `${R}/db/${d}`);
    for (const d of refFiles) if (!kept.includes(d)) await rclone('deletefile', `${R}/files/refs/${d}.txt`);
    if (refFiles.length) {
      const keptRefs = [];
      for (const d of refFiles.filter((x) => kept.includes(x))) keptRefs.push(parseRefs((await rclone('cat', `${R}/files/refs/${d}.txt`)).out));
      if (keptRefs.length && keptRefs.every((m) => m.size)) {
        const objs = ((await lsf(R + '/files/objects/')) || []).map((f) => f.replace(/\.age$/, ''));
        const mans = ((await lsf(R + '/files/manifests/')) || []).map((f) => f.replace(/\.json\.age$/, '')).filter((s) => STAMP_RE.test(s));
        const p = pruneSets(keptRefs, objs, mans);
        if (p.objects.length) { writeFileSync(join(T(), 'gone.txt'), p.objects.map((id) => id + '.age').join('\n') + '\n'); await rclone('delete', `${R}/files/objects/`, '--files-from-raw', join(T(), 'gone.txt')); }
        for (const st of p.manifests) await rclone('deletefile', `${R}/files/manifests/${st}.json.age`);
      }
    }
    writeJson('dates.json', datesMap(db.filter((d) => kept.includes(d)), refFiles.filter((d) => kept.includes(d)), kept));
  },
  receipt: async () => {
    const t = T(), kind = env('VAULT_KIND') === 'restore' ? 'restore' : 'backup';
    // The first step that did not succeed names the error (steps.<id>.outcome from the workflow, in order).
    const steps = env('VAULT_STEPS').split(/\s+/).filter(Boolean).map((s) => s.split('='));
    const failedStep = steps.find(([, o]) => o === 'failure');
    let err = failedStep ? failedStep[0] : undefined;
    if (err === 'dump') { try { err = readFileSync(join(t, 'err'), 'utf8').trim() || 'dump'; } catch { /* dump */ } }
    if (err === 'tools' || err === 'prepare' || err === 'pick') err = 'config';
    const ok = !failedStep && steps.length > 0 && steps.every(([, o]) => o === 'success' || o === 'skipped');
    const db = readJson(join(t, 'db.json')), dates = readJson(join(t, 'dates.json'));
    const files = kind === 'backup' ? readJson(join(t, 'files.json')) || (env('VAULT_FILES_SRC') ? null : { st: 'none' }) : null;
    const chk = readJson(join(t, 'db-check.json')), fr = readJson(join(t, 'files-restore.json'));
    const outcome = (id) => (steps.find(([s]) => s === id) || [])[1];
    const body = buildReceipt({
      kind, wf: Number(env('VAULT_WF')), ok, err, started: env('VAULT_STARTED'), finished: new Date().toISOString(), pg: Number(env('VAULT_PG')), remote: env('VAULT_REMOTE_KIND'),
      db: kind === 'backup' ? db : undefined, files: files || undefined, dates,
      keep: { d: Number(env('VAULT_KEEP_D')), w: Number(env('VAULT_KEEP_W')), m: Number(env('VAULT_KEEP_M')) },
      restore: kind === 'restore' ? { mode: env('VAULT_MODE'), target: env('VAULT_TARGET'), date: env('VAULT_DATE'), db: outcome('db') === 'skipped' || !outcome('db') ? 'skip' : chk && chk.ok ? 'pass' : 'fail', files: outcome('files') === 'skipped' || !outcome('files') ? 'skip' : fr && fr.result === 'pass' ? 'pass' : 'fail', sample: fr ? fr.sample : 0, errors: chk ? chk.errors : 0 } : undefined,
    });
    const text = JSON.stringify(body);
    console.log(`Receipt: ${kind}, ${ok ? 'ok' : 'not ok (' + (body.err || '') + ')'}, ${text.length} bytes.`);
    const reqUrl = env('ACTIONS_ID_TOKEN_REQUEST_URL'), reqTok = env('ACTIONS_ID_TOKEN_REQUEST_TOKEN'), to = env('VAULT_RECEIPT_URL');
    if (!reqUrl || !reqTok || !/^https:\/\/7it\.co\.il\//.test(to)) { console.log('Receipt not sent: the run has no identity token (id-token: write) or no address.'); process.exit(1); }
    for (let i = 0; i < 3; i++) {
      try {
        const tk = await fetch(`${reqUrl}&audience=${RECEIPT_AUDIENCE}`, { headers: { Authorization: `Bearer ${reqTok}` } }).then((r) => r.json());
        const r = await fetch(to, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tk.value}` }, body: text, signal: AbortSignal.timeout(15000) });
        if (r.ok) { const a = await r.json().catch(() => ({})); if (a.update) console.log('A newer vault workflow is ready. Re-run the 7IT Guard vault setup when convenient.'); return; }
        if (r.status === 503 || r.status === 404 || r.status === 409) { console.log(`Receipt not accepted (${r.status}).`); return; }
      } catch { /* retried */ }
      await new Promise((s) => setTimeout(s, 3000 * (i + 1)));
    }
    console.log('Receipt not sent after 3 tries. Your backup is not affected.'); process.exit(1);
  },
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [cmd, ...args] = process.argv.slice(2);
  if (!commands[cmd]) { console.log('unknown command'); process.exit(2); }
  await commands[cmd](...args);
}
