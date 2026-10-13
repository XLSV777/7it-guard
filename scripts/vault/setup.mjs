#!/usr/bin/env node
// 7IT Guard backup vault: the setup helper behind /7it-guard:vault (plugin 0.4.0; plan: https://7it.co.il/tools/guard/).
// Node 18 or newer, built-ins only, run from the root of the app's repository on the owner's own machine. Every step prints
// one JSON object. Nothing here ever prints a password, a database address, a storage key or a private key: secrets go from
// the project's own env files (or the local file .7it-vault.env, kept out of git) straight into `gh secret set` through stdin.
//
//   detect                      what the project uses: repository, branch, platform, database variable (its NAME only), stored
//                               files, storage, time zone, an existing vault workflow; and what is still missing
//   guide --builder lovable|bolt   Lovable Cloud or Bolt Database: the manual path in plain words (move to your own Supabase;
//                               until then the platform's export button once a month), the label "Manual, not automatic"
//   ask-db                      the data is in the owner's own Supabase after all: an empty VAULT_DATABASE_URL line to fill
//   keys --repo o/n             the two key pairs (age X25519, made here in Node): the owner key is written to
//                               ~/.7it-guard/vault/<o>-<n>-key.txt (only the owner can read it); the restore-test key's private
//                               half goes straight into the GitHub secret VAULT_AGE_KEY and is never written to disk. Run again:
//                               both keys are kept (old backups stay readable) unless --new-keys / --renew-test-key
//   role-sql --repo o/n         a read-only database sign-in: writes the SQL (with a new random password) to
//                               ~/.7it-guard/vault/<o>-<n>-readonly.sql and prints it with the password hidden
//   role-run --repo o/n         runs that SQL with psql when psql is installed (only after the owner said yes)
//   db-secret --repo o/n [--readonly]   sets VAULT_DATABASE_URL (the address GitHub can reach: Supabase session pooler,
//                               Neon without -pooler) and, when present, VAULT_RESTORE_DATABASE_URL
//   storage --repo o/n --files supabase|s3|none   builds the storage settings and sets VAULT_RCLONE_CONFIG, or lists the
//                               missing values and writes them as empty lines into .7it-vault.env
//   write --recipient age1.. --ci age1.. --repo o/n [--files ..] [--remote-path ..] [--remote-kind ..] [--pg 17] [--tz ..]
//                               writes .github/workflows/7it-vault.yml and 7it-vault-restore.yml and prints the schedule and
//                               the fields for the registration (the plugin's vault_register tool)
//   start --repo o/n            starts the first backup, then the first restore test (queued right after it)
//   cleanup --repo o/n          removes .7it-vault.env and the read-only SQL file (after the owner said yes)
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync, readdirSync, statSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { vaultFiles, scheduleFor, VAULT_WF_VERSION, workflowVersionOf, BACKUP_PATH, KEEP_DEFAULT, PINS } from './workflow.mjs';

const CWD = process.cwd();
const ARGS = process.argv.slice(2);
const opt = (k, d) => { const i = ARGS.indexOf('--' + k); return i > 0 && i + 1 < ARGS.length ? ARGS[i + 1] : d; };
const flag = (k) => ARGS.includes('--' + k);
const say = (o) => process.stdout.write(JSON.stringify(o, null, 1) + '\n');
const stop = (error, extra = {}) => { say({ ok: false, error, ...extra }); process.exit(1); };
const REPO_RE = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
export const LOCAL_ENV = '.7it-vault.env';
const KEY_DIR = join(homedir(), '.7it-guard', 'vault');
const slugOf = (repo) => repo.replace('/', '-').replace(/[^A-Za-z0-9_.-]/g, '_');

// ---------------------------------------------------------------- bech32 (BIP 173) and age X25519 key pairs
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(values) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) { const b = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i]; }
  return chk >>> 0;
}
const hrpExpand = (hrp) => [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
function toWords(bytes) {
  let acc = 0, bits = 0;
  const out = [];
  for (const b of bytes) { acc = ((acc << 8) | b) & 0xffff; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >> bits) & 31); } }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
}
export function bech32Encode(hrp, bytes) {
  const data = toWords(bytes), pm = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  return hrp + '1' + [...data, ...[0, 1, 2, 3, 4, 5].map((i) => (pm >>> (5 * (5 - i))) & 31)].map((d) => CHARSET[d]).join('');
}
export function bech32Valid(s) {
  const str = String(s).toLowerCase(), p = str.lastIndexOf('1');
  if (p < 1 || p + 7 > str.length) return false;
  const data = [...str.slice(p + 1)].map((c) => CHARSET.indexOf(c));
  return !data.some((d) => d < 0) && polymod([...hrpExpand(str.slice(0, p)), ...data]) === 1;
}
// An age X25519 identity (AGE-SECRET-KEY-1...) and its recipient (age1...), made with Node's own X25519.
export function ageKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url'), priv = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  return { recipient: bech32Encode('age', pub), identity: bech32Encode('age-secret-key-', priv).toUpperCase() };
}

// ---------------------------------------------------------------- the project's env files (values stay in this process)
const ENV_FILES = ['.env', '.env.development', '.env.development.local', '.env.production', '.env.production.local', '.env.local', LOCAL_ENV];
export function parseEnv(text) {
  const vars = {};
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!m) continue;
    let v = m[2];
    if (/^(['"]).*\1$/.test(v)) v = v.slice(1, -1); else v = v.replace(/(^|\s+)#.*$/, '');
    if (v) vars[m[1]] = v;
  }
  return vars;
}
function readEnv() {
  const vars = {}, from = {};
  for (const f of ENV_FILES) { const p = join(CWD, f); if (!existsSync(p)) continue; const e = parseEnv(readFileSync(p, 'utf8')); for (const [k, v] of Object.entries(e)) { vars[k] = v; from[k] = f; } }
  return { vars, from };
}
const readJson = (p) => { try { return JSON.parse(readFileSync(join(CWD, p), 'utf8')); } catch { return null; } };
const readText = (p) => { try { return readFileSync(join(CWD, p), 'utf8'); } catch { return ''; } };

// ---------------------------------------------------------------- the database address: which variable, and the address GitHub can reach
export const DB_VARS = ['VAULT_DATABASE_URL', 'SUPABASE_DB_URL', 'DATABASE_URL_UNPOOLED', 'POSTGRES_URL_NON_POOLING', 'DIRECT_URL', 'DIRECT_DATABASE_URL', 'DATABASE_URL', 'POSTGRES_URL', 'POSTGRES_PRISMA_URL', 'NEON_DATABASE_URL', 'PG_URL'];
export const dbVarOf = (vars) => DB_VARS.find((k) => /^postgres(?:ql)?:\/\//i.test(vars[k] || '')) || null;
// GitHub's runners reach IPv4 only: Supabase's direct host is IPv6 only (use the session pooler, port 5432; the transaction
// pooler on 6543 cannot dump), Neon's pooled host is swapped for the unpooled one, PlanetScale Postgres 6432 for 5432.
export function dbPlan(url) {
  let u;
  try { u = new URL(url); } catch { return { ok: false, why: 'unreadable' }; }
  if (!/^postgres(?:ql)?:$/.test(u.protocol)) return { ok: false, why: 'not_postgres' };
  const host = u.hostname, port = u.port || '5432';
  if (/\.pooler\.supabase\.com$/.test(host)) { const ref = (/^postgres\.([a-z0-9]{20})$/.exec(decodeURIComponent(u.username)) || [])[1] || null, region = (/^aws-\d+-([a-z0-9-]+)\.pooler/.exec(host) || [])[1] || null; if (port === '6543') u.port = '5432'; return { ok: true, platform: 'supabase', kind: 'session_pooler', fixed: port === '6543' ? 'session_port' : null, ref, region, url: u.toString() }; }
  if (/^db\.[a-z0-9]{20}\.supabase\.co$/.test(host)) return { ok: false, platform: 'supabase', why: 'supabase_direct', ref: host.split('.')[1] };
  if (/\.neon\.tech$/.test(host)) { const un = host.replace(/-pooler(?=\.)/, ''); if (un !== host) u.hostname = un; return { ok: true, platform: 'neon', kind: 'unpooled', fixed: un !== host ? 'unpooled' : null, url: u.toString() }; }
  if (/(^|\.)(psdb\.cloud|planetscale\.com|pg\.psdb\.cloud)$/.test(host)) { if (port === '6432') u.port = '5432'; return { ok: true, platform: 'planetscale', kind: 'direct', fixed: port === '6432' ? 'direct_port' : null, url: u.toString() }; }
  return { ok: true, platform: /replit/.test(host) ? 'replit' : 'postgres', kind: 'direct', fixed: null, url: u.toString() };
}
// The read-only sign-in in place of the owner's (Supabase's pooler wants "<role>.<project ref>").
export function withRole(url, role, password) {
  const u = new URL(url), cur = decodeURIComponent(u.username), m = /^[^.]+\.([a-z0-9]{20})$/.exec(cur);
  u.username = encodeURIComponent(m ? `${role}.${m[1]}` : role); u.password = encodeURIComponent(password);
  return u.toString();
}

// ---------------------------------------------------------------- what the project uses
function walk(dir, max, out = []) {
  if (out.length >= max || !existsSync(dir)) return out;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (out.length >= max) break;
    if (['node_modules', '.git', '.next', 'dist', 'build', '.vercel', '.output', 'coverage'].includes(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, max, out); else if (/\.(m?[jt]sx?|vue|svelte|astro)$/.test(e.name)) out.push(p);
  }
  return out;
}
const usesStorage = () => walk(CWD, 4000).some((p) => { try { return statSync(p).size < 400_000 && /\.storage\s*\.from\(/.test(readFileSync(p, 'utf8')); } catch { return false; } });
const gh = (a, input) => { const r = spawnSync('gh', a, { encoding: 'utf8', input, windowsHide: true }); return { ok: r.status === 0, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() }; };
export const SUPA_URL_VARS = ['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL', 'VITE_SUPABASE_URL', 'PUBLIC_SUPABASE_URL', 'EXPO_PUBLIC_SUPABASE_URL', 'REACT_APP_SUPABASE_URL'];
function supaRef(vars) {
  for (const k of SUPA_URL_VARS) { const m = /^https:\/\/([a-z0-9]{20})\.supabase\.co/.exec(vars[k] || ''); if (m) return m[1]; }
  return (/project_id\s*=\s*"([a-z0-9]{20})"/.exec(readText('supabase/config.toml')) || [])[1] || null;
}
export function storagePick(vars) {
  const store = (vars.VAULT_STORE || 'r2').toLowerCase();
  const need = store === 'r2' ? ['VAULT_STORE_BUCKET', 'VAULT_R2_ACCOUNT_ID', 'VAULT_STORE_KEY_ID', 'VAULT_STORE_SECRET'] : store === 's3' ? ['VAULT_STORE_BUCKET', 'VAULT_S3_REGION', 'VAULT_STORE_KEY_ID', 'VAULT_STORE_SECRET'] : store === 'b2' ? ['VAULT_STORE_BUCKET', 'VAULT_STORE_KEY_ID', 'VAULT_STORE_SECRET'] : null;
  if (!need) return { store, missing: ['VAULT_STORE'] };
  return { store, missing: need.filter((k) => !vars[k]) };
}
const builderOf = (deps) => (existsSync(join(CWD, '.bolt')) ? 'bolt' : deps['lovable-tagger'] ? 'lovable' : null);
function detect() {
  const { vars, from } = readEnv();
  const pkg = readJson('package.json') || {}, deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const ghv = gh(['--version']), auth = ghv.ok ? gh(['auth', 'status']) : { ok: false };
  let repo = null;
  if (auth.ok) {
    const v = gh(['repo', 'view', '--json', 'nameWithOwner,defaultBranchRef,visibility']);
    if (v.ok) { try { const j = JSON.parse(v.out), id = gh(['api', `repos/${j.nameWithOwner}`, '--jq', '.id']); repo = { name: j.nameWithOwner, id: id.ok ? id.out : null, branch: j.defaultBranchRef?.name || null, visibility: String(j.visibility || '').toLowerCase() }; } catch { repo = null; } }
  }
  const dbVar = dbVarOf(vars), plan = dbVar ? dbPlan(vars[dbVar]) : null, ref = supaRef(vars);
  const supa = !!ref || !!deps['@supabase/supabase-js'] || plan?.platform === 'supabase';
  const platform = plan?.platform || (supa ? 'supabase' : deps['@neondatabase/serverless'] ? 'neon' : deps['@planetscale/database'] ? 'planetscale' : existsSync(join(CWD, '.replit')) ? 'replit' : deps.firebase || deps['firebase-admin'] ? 'firebase' : deps.mysql2 || deps.mysql ? 'mysql' : 'unknown');
  const builder = builderOf(deps);
  const files = supa && usesStorage() ? 'supabase' : deps['@aws-sdk/client-s3'] || vars.S3_BUCKET || vars.AWS_S3_BUCKET || vars.R2_BUCKET || vars.VAULT_FILES_BUCKET ? 's3' : 'none';
  const major = Number((/major_version\s*=\s*(\d+)/.exec(readText('supabase/config.toml')) || [])[1] || 0);
  const pg = major >= 18 ? 18 : 17; // a newer client dumps older servers; 18 only for an 18 server
  const wf = readText(BACKUP_PATH), recips = (/VAULT_RECIPIENTS: '([^']*)'/.exec(wf) || [])[1] || '';
  const sp = storagePick(vars);
  const missing = [];
  if (!ghv.ok) missing.push('gh_cli'); else if (!auth.ok) missing.push('gh_login');
  if (ghv.ok && auth.ok && !repo) missing.push('github_repo');
  if (!dbVar) missing.push(builder ? 'database_address_or_builder_cloud' : 'database_address');
  else if (!plan.ok) missing.push(plan.why === 'supabase_direct' ? 'supabase_session_pooler_address' : 'database_address');
  if (sp.missing.length) missing.push('backup_storage');
  if (files === 'supabase' && !(vars.VAULT_FILES_KEY_ID && vars.VAULT_FILES_SECRET)) missing.push('supabase_storage_access_keys');
  say({
    ok: true, repo, tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC', platform, builder, ask_cloud: cloudStop(builder, vars),
    database: dbVar ? { variable: dbVar, file: from[dbVar], reachable: !!plan?.ok, kind: plan?.kind || null, fixed: plan?.fixed || null, why: plan?.ok ? null : plan?.why || null } : null,
    supabase_ref: ref, files, pg, storage: { kind: sp.store, missing: sp.missing }, restore_database: !!vars.VAULT_RESTORE_DATABASE_URL,
    existing: wf ? { version: workflowVersionOf(wf), latest: VAULT_WF_VERSION, keys_kept: recips.split(' ').filter(Boolean).length >= 2 } : null,
    key_file: repo ? join(KEY_DIR, slugOf(repo.name) + '-key.txt') : null, key_file_exists: repo ? existsSync(join(KEY_DIR, slugOf(repo.name) + '-key.txt')) : false,
    site_hints: [pkg.homepage, readText('public/CNAME').trim() || null, readText('CNAME').trim() || null].filter(Boolean),
    keep: KEEP_DEFAULT, missing,
  });
}

// ---------------------------------------------------------------- Lovable Cloud and Bolt Database: the manual path (0.4.0, vault V6)
// These platforms give no database address, so no nightly copy can run there: `write` refuses, and `guide` prints the two paths
// (move to the owner's own Supabase; until then the platform's own export button once a month). The same words as the 7IT Guard
// app's vault card (scripts/guard-app/vault.js guideText in the 7IT repository). Nothing here reads the app's data.
export const MANUAL_LABEL = 'Manual, not automatic';
export function manualGuide(p) {
  if (p === 'lovable') return {
    name: 'Lovable Cloud',
    why: 'Lovable Cloud gives no database address, so a nightly copy cannot run by itself. Backups here are manual, not automatic.',
    check: 'Not sure? In Lovable, click the Cloud icon on the top bar. Tables and users inside Lovable mean Lovable Cloud. A Supabase project name means your own Supabase: use the setup prompt instead.',
    move: { title: 'Move to your own Supabase', text: 'Lovable has no one-step move: export your Cloud data, connect your own Supabase project in a new Lovable project, rebuild the tables there and bring the data in. After that, the vault backs up every night by itself.', prompt: 'I am moving this app from Lovable Cloud to my own Supabase project. In this project, which is connected to my own Supabase, recreate every table, security policy, storage bucket and function the app uses, as database migrations, so I can bring in the data I exported from Lovable Cloud. Show me the plan before you change anything. Do not delete any data.', doc: 'https://docs.lovable.dev/integrations/cloud' },
    export: { title: 'Until then, export once a month', text: 'In Lovable, open More, then Cloud, then Overview, then Advanced settings, and press Export data. Lovable emails you a link. Download the file and keep it somewhere you own. It holds the database, not your stored files.', doc: 'https://docs.lovable.dev/features/advanced-settings' },
  };
  if (p === 'bolt') return {
    name: 'Bolt Database',
    why: 'Bolt Database gives no database address, so a nightly copy cannot run by itself. Backups here are manual, not automatic.',
    check: 'Not sure? In Bolt, click the Database icon at the top. If your project is connected to your own Supabase instead, use the setup prompt.',
    move: { title: 'Claim it into your own Supabase', text: 'In Bolt, click the Database icon, open Advanced and press Claim, then finish in Supabase. It needs a Bolt Pro or Teams plan and a Supabase organization you own. After that, the vault backs up every night by itself.', prompt: null, doc: 'https://support.bolt.new/integrations/supabase.md' },
    export: { title: 'Until then, export once a month', text: 'In Bolt, click the Database icon, pick a table, tick all rows and press Export, as a spreadsheet file or as JSON. Do it for each table and keep the files somewhere you own.', doc: 'https://support.bolt.new/cloud/database/tables' },
  };
  return null;
}
// A builder project with no database address in its env files: the owner must say first whether the data is in their own
// Supabase (then VAULT_DATABASE_URL goes into .7it-vault.env) or in Lovable Cloud / Bolt Database (the manual path, no workflow).
export const cloudStop = (builder, vars) => !!builder && !dbVarOf(vars || {});
function guide() {
  const b = opt('builder', '');
  const g = manualGuide(b);
  if (!g) stop('builder', { message: '--builder must be lovable or bolt' });
  say({ ok: true, builder: b, label: MANUAL_LABEL, ...g, reminder: { tool: 'vault_register', fields: { manual: b }, what: 'a monthly reminder in the 7IT Guard app to press the export button' } });
}
// The owner's data is in their own Supabase after all: an empty VAULT_DATABASE_URL line in .7it-vault.env to fill.
function askDb() { const t = writeTemplate(['VAULT_DATABASE_URL']); say({ ok: true, file: t.file, name: 'VAULT_DATABASE_URL' }); }

// ---------------------------------------------------------------- keys
function repoArg() { const r = opt('repo', ''); if (!REPO_RE.test(r)) stop('repo', { message: 'Pass --repo owner/name.' }); return r; }
function keys() {
  const repo = repoArg(), file = join(KEY_DIR, slugOf(repo) + '-key.txt');
  mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  let recipient = null, newOwner = false;
  if (existsSync(file) && !flag('new-keys')) recipient = (/^# public key: (age1[02-9ac-hj-np-z]{58})$/m.exec(readFileSync(file, 'utf8')) || [])[1] || null;
  if (!recipient) {
    const k = ageKeyPair();
    writeFileSync(file, `# 7IT Guard backup vault key for ${repo}. Keep it in your password manager.\n# Without it nobody, including 7IT, can open your backups.\n# created: ${new Date().toISOString()}\n# public key: ${k.recipient}\n${k.identity}\n`, { mode: 0o600 });
    recipient = k.recipient; newOwner = true;
  }
  const wf = readText(BACKUP_PATH), cur = ((/VAULT_RECIPIENTS: '([^']*)'/.exec(wf) || [])[1] || '').split(' ').filter(Boolean);
  let ci = !flag('renew-test-key') && !flag('new-keys') && cur.length >= 2 && cur[1] !== recipient ? cur[1] : null, testSet = false;
  if (!ci) {
    const t = ageKeyPair();
    const r = gh(['secret', 'set', 'VAULT_AGE_KEY', '--repo', repo], t.identity + '\n');
    if (!r.ok) stop('secret_not_set', { name: 'VAULT_AGE_KEY', message: 'gh could not set the secret. Check that gh is signed in with access to this repository.' });
    ci = t.recipient; testSet = true;
  }
  say({ ok: true, recipient, ci, key_file: file, new_owner_key: newOwner, test_key_set: testSet });
}

// ---------------------------------------------------------------- the read-only sign-in
const roleFile = (repo) => join(KEY_DIR, slugOf(repo) + '-readonly.sql');
export const ROLE = 'vault_reader';
export function roleSql(password) {
  return `-- 7IT Guard backup vault: a database sign-in that can only read (PostgreSQL 14 or newer).
create role ${ROLE} with login password '${password}';
grant pg_read_all_data to ${ROLE};
-- If your database refuses the line above, use these instead (they cover the usual schemas):
-- grant usage on schema public, auth, storage to ${ROLE};
-- grant select on all tables in schema public, auth, storage to ${ROLE};
-- grant select on all sequences in schema public, auth, storage to ${ROLE};
`;
}
function roleSqlCmd() {
  const repo = repoArg(), f = roleFile(repo);
  mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  const pw = existsSync(f) && !flag('new') ? (/password '([A-Za-z0-9]{32})'/.exec(readFileSync(f, 'utf8')) || [])[1] : null;
  const password = pw || randomBytes(24).toString('base64').replace(/[^A-Za-z0-9]/g, '').padEnd(32, 'x').slice(0, 32);
  writeFileSync(f, roleSql(password), { mode: 0o600 });
  say({ ok: true, file: f, role: ROLE, sql: roleSql('********') });
}
function dbUrl() {
  const { vars } = readEnv(), v = dbVarOf(vars);
  if (!v) stop('no_database_address', { message: 'No database address was found in the env files.' });
  const p = dbPlan(vars[v]);
  if (!p.ok && p.why === 'supabase_direct') writeTemplate(['VAULT_DATABASE_URL']);
  if (!p.ok) stop(p.why, { message: p.why === 'supabase_direct' ? 'This is the direct address, which GitHub cannot reach. Put the Session pooler address (Supabase: Connect, then Session pooler) as VAULT_DATABASE_URL in .7it-vault.env.' : 'The database address could not be read.' });
  return { p, vars };
}
function roleRun() {
  const repo = repoArg(), f = roleFile(repo);
  if (!existsSync(f)) stop('no_sql', { message: 'Run role-sql first.' });
  if (spawnSync('psql', ['--version'], { encoding: 'utf8', windowsHide: true }).status !== 0) stop('no_psql', { message: 'psql is not installed. Paste the SQL file into your database\'s SQL editor instead.' });
  const { p } = dbUrl();
  const r = spawnSync('psql', [p.url, '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-f', f], { encoding: 'utf8', windowsHide: true });
  say({ ok: r.status === 0, ...(r.status === 0 ? {} : { error: 'sql_failed', message: /permission denied|must have admin/i.test(r.stderr || '') ? 'The database refused pg_read_all_data. Use the other lines in the SQL file.' : /already exists/i.test(r.stderr || '') ? 'The read-only sign-in already exists. Nothing to do, or run role-sql --new to make a new password.' : 'The SQL did not run.' }) });
}
function dbSecret() {
  const repo = repoArg(), { p, vars } = dbUrl();
  let url = p.url;
  if (flag('readonly')) { const m = /password '([A-Za-z0-9]{32})'/.exec(existsSync(roleFile(repo)) ? readFileSync(roleFile(repo), 'utf8') : ''); if (!m) stop('no_sql', { message: 'Run role-sql first.' }); url = withRole(url, ROLE, m[1]); }
  if (!gh(['secret', 'set', 'VAULT_DATABASE_URL', '--repo', repo], url).ok) stop('secret_not_set', { name: 'VAULT_DATABASE_URL' });
  let restore = false;
  if (vars.VAULT_RESTORE_DATABASE_URL) { const rp = dbPlan(vars.VAULT_RESTORE_DATABASE_URL); if (rp.ok && gh(['secret', 'set', 'VAULT_RESTORE_DATABASE_URL', '--repo', repo], rp.url).ok) restore = true; }
  say({ ok: true, platform: p.platform, kind: p.kind, fixed: p.fixed, readonly: flag('readonly'), restore_database_set: restore });
}

// ---------------------------------------------------------------- storage (the backup place, the stored-files source, the restore place)
export function rcloneConfig(vars, o) {
  const g = (k) => String(vars[k] || '').replace(/[\r\n]/g, '');
  const sp = storagePick(vars), lines = [];
  const missing = [...sp.missing];
  const bucket = g('VAULT_STORE_BUCKET').replace(/^\/+|\/+$/g, ''), name = String(o.repo || 'app').split('/')[1] || 'app';
  if (sp.store === 'r2') lines.push('[vault]', 'type = s3', 'provider = Cloudflare', `access_key_id = ${g('VAULT_STORE_KEY_ID')}`, `secret_access_key = ${g('VAULT_STORE_SECRET')}`, `endpoint = https://${g('VAULT_R2_ACCOUNT_ID')}.r2.cloudflarestorage.com`, 'acl = private', 'no_check_bucket = true', '');
  else if (sp.store === 's3') lines.push('[vault]', 'type = s3', 'provider = AWS', 'env_auth = false', `access_key_id = ${g('VAULT_STORE_KEY_ID')}`, `secret_access_key = ${g('VAULT_STORE_SECRET')}`, `region = ${g('VAULT_S3_REGION')}`, 'acl = private', 'no_check_bucket = true', '');
  else if (sp.store === 'b2') lines.push('[vault]', 'type = b2', `account = ${g('VAULT_STORE_KEY_ID')}`, `key = ${g('VAULT_STORE_SECRET')}`, '');
  if (o.files === 'supabase') {
    for (const k of ['VAULT_FILES_KEY_ID', 'VAULT_FILES_SECRET']) if (!vars[k]) missing.push(k);
    if (!o.ref) missing.push('SUPABASE_URL');
    lines.push('[src-files]', 'type = s3', 'provider = Other', `access_key_id = ${g('VAULT_FILES_KEY_ID')}`, `secret_access_key = ${g('VAULT_FILES_SECRET')}`, `endpoint = https://${o.ref}.storage.supabase.co/storage/v1/s3`, `region = ${g('VAULT_FILES_REGION') || o.region || 'us-east-1'}`, 'force_path_style = true', '');
  } else if (o.files === 's3') {
    const id = g('VAULT_FILES_KEY_ID') || g('AWS_ACCESS_KEY_ID') || g('S3_ACCESS_KEY_ID') || g('R2_ACCESS_KEY_ID'), sec = g('VAULT_FILES_SECRET') || g('AWS_SECRET_ACCESS_KEY') || g('S3_SECRET_ACCESS_KEY') || g('R2_SECRET_ACCESS_KEY');
    const fb = g('VAULT_FILES_BUCKET') || g('S3_BUCKET') || g('AWS_S3_BUCKET') || g('R2_BUCKET'), r2 = g('R2_ACCOUNT_ID'), ep = g('VAULT_FILES_ENDPOINT') || g('S3_ENDPOINT') || (r2 ? `https://${r2}.r2.cloudflarestorage.com` : '');
    if (!id) missing.push('VAULT_FILES_KEY_ID'); if (!sec) missing.push('VAULT_FILES_SECRET'); if (!fb) missing.push('VAULT_FILES_BUCKET');
    lines.push('[src-raw]', 'type = s3', `provider = ${ep ? (r2 ? 'Cloudflare' : 'Other') : 'AWS'}`, 'env_auth = false', `access_key_id = ${id}`, `secret_access_key = ${sec}`, ...(ep ? [`endpoint = ${ep}`] : [`region = ${g('AWS_REGION') || g('S3_REGION') || 'us-east-1'}`]), '', '[src-files]', 'type = alias', `remote = src-raw:${fb}`, '');
  }
  // Restores write to a NEW place: a folder of its own in the backup bucket (never the live storage).
  if (bucket) lines.push('[restore-files]', 'type = alias', `remote = vault:${bucket}/${name}-restore`, '');
  return { missing: [...new Set(missing)], config: lines.join('\n'), remotePath: bucket ? `${bucket}/${name}` : '', remoteKind: sp.store === 'r2' || sp.store === 's3' || sp.store === 'b2' ? sp.store : 'other' };
}
// The values the setup cannot find itself: [default, where to find it]. The owner fills them in .7it-vault.env.
const TEMPLATE = {
  VAULT_STORE: ['r2', 'where the backups live: r2 (Cloudflare R2, the default), s3 or b2'],
  VAULT_STORE_BUCKET: ['', 'a NEW, empty bucket only for backups'],
  VAULT_R2_ACCOUNT_ID: ['', 'Cloudflare: the account id (R2 overview page)'],
  VAULT_S3_REGION: ['', 'Amazon S3 only, for example us-east-1'],
  VAULT_STORE_KEY_ID: ['', 'an access key limited to that one bucket'],
  VAULT_STORE_SECRET: ['', 'its secret'],
  VAULT_FILES_KEY_ID: ['', 'Supabase: Storage, then S3 access keys, then New access key'],
  VAULT_FILES_SECRET: ['', 'its secret'],
  VAULT_FILES_BUCKET: ['', 'the bucket your app stores files in (S3 or R2 apps)'],
  SUPABASE_URL: ['', 'your Supabase project address (Project Settings, then API)'],
  VAULT_DATABASE_URL: ['', 'Supabase: Connect, then Session pooler, the address with your database password in it'],
};
function excludeLocal() {
  const ex = join(CWD, '.git', 'info', 'exclude');
  if (!existsSync(join(CWD, '.git'))) return;
  mkdirSync(join(CWD, '.git', 'info'), { recursive: true });
  if (!(existsSync(ex) ? readFileSync(ex, 'utf8') : '').split(/\r?\n/).includes(LOCAL_ENV)) appendFileSync(ex, `\n${LOCAL_ENV}\n`);
}
export function templateText(cur, names) {
  const listed = new Set([...String(cur).matchAll(/^\s*([A-Z_0-9]+)\s*=/gm)].map((m) => m[1]));
  const add = [...new Set(names)].filter((k) => !listed.has(k)).map((k) => { const [d, w] = TEMPLATE[k] || ['', '']; return `${k}=${d}${w ? '   # ' + w : ''}`; });
  return add.length ? String(cur).replace(/\n*$/, '\n') + add.join('\n') + '\n' : String(cur);
}
function writeTemplate(names) {
  excludeLocal();
  const p = join(CWD, LOCAL_ENV), cur = existsSync(p) ? readFileSync(p, 'utf8') : '# 7IT Guard backup vault: values for the setup only. Kept out of git; removed when the setup is done.\n';
  writeFileSync(p, templateText(cur, names), { mode: 0o600 });
  return { file: p };
}
function storage() {
  const repo = repoArg(), files = opt('files', 'none');
  if (!['none', 'supabase', 's3'].includes(files)) stop('files', { message: '--files must be none, supabase or s3' });
  const { vars } = readEnv(), dp = dbVarOf(vars) ? dbPlan(vars[dbVarOf(vars)]) : null;
  const c = rcloneConfig(vars, { repo, files, ref: supaRef(vars), region: dp?.region || null });
  if (c.missing.length) { const t = writeTemplate(['VAULT_STORE', ...c.missing]); say({ ok: false, error: 'missing', missing: c.missing, file: t.file }); process.exit(1); }
  if (!gh(['secret', 'set', 'VAULT_RCLONE_CONFIG', '--repo', repo], c.config).ok) stop('secret_not_set', { name: 'VAULT_RCLONE_CONFIG' });
  say({ ok: true, remote_kind: c.remoteKind, remote_path: c.remotePath, files, restore_place: true });
}

// ---------------------------------------------------------------- the two workflow files, the first run, cleanup
function write() {
  // Never a workflow for Lovable Cloud or Bolt Database: without a database address it could only fail every night.
  const pkg = readJson('package.json') || {}, deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  if (cloudStop(builderOf(deps), readEnv().vars)) stop('builder_cloud', { message: 'No database address was found. On Lovable Cloud or Bolt Database a nightly copy cannot run: run guide --builder lovable|bolt. On your own Supabase: run ask-db and fill the line.' });
  const repo = repoArg(), tz = opt('tz', Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'), hour = Number(opt('hour', 3));
  const o = { recipient: opt('recipient'), ci: opt('ci'), pg: Number(opt('pg', 17)), files: opt('files', 'none'), remotePath: opt('remote-path'), remoteKind: opt('remote-kind', 'other'), tz, hour, seed: repo };
  let files;
  try { files = vaultFiles(o); } catch (e) { stop('bad_option', { message: String(e.message || e) }); }
  for (const f of files) { mkdirSync(join(CWD, '.github', 'workflows'), { recursive: true }); writeFileSync(join(CWD, f.path), f.text); }
  const s = scheduleFor({ tz, hour, seed: repo });
  say({ ok: true, files: files.map((f) => f.path), schedule: { local: s.local, tz, utc: s.cron, restore: s.restoreCron }, keep: KEEP_DEFAULT, pg: o.pg, tools: { age: PINS.age.version, rclone: PINS.rclone.version },
    register: { repo, cron: s.cron, restore_dow: s.restoreDow, tz, files: o.files !== 'none', wf: VAULT_WF_VERSION } });
}
function start() {
  const repo = repoArg();
  const b = gh(['workflow', 'run', '7it-vault.yml', '--repo', repo]);
  if (!b.ok) stop('not_started', { message: 'The first backup did not start. The workflow files must be on the default branch on GitHub first.' });
  const r = gh(['workflow', 'run', '7it-vault-restore.yml', '--repo', repo, '-f', 'date=latest', '-f', 'mode=full', '-f', 'target=check']);
  say({ ok: true, backup: true, restore_test: r.ok, note: 'The restore test waits for the backup to finish, then runs.' });
}
function cleanup() {
  const repo = repoArg(), gone = [];
  for (const p of [join(CWD, LOCAL_ENV), roleFile(repo)]) if (existsSync(p)) { try { writeFileSync(p, '0'.repeat(Math.max(1, statSync(p).size))); unlinkSync(p); gone.push(p); } catch { /* left */ } }
  say({ ok: true, removed: gone });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const C = { detect, guide, 'ask-db': askDb, keys, 'role-sql': roleSqlCmd, 'role-run': roleRun, 'db-secret': dbSecret, storage, write, start, cleanup }[ARGS[0]];
  if (!C) stop('usage', { message: 'detect | guide | ask-db | keys | role-sql | role-run | db-secret | storage | write | start | cleanup' });
  C();
}
