#!/usr/bin/env node
// 7IT Guard 0.3.1: checks a deployed web app from the outside, on YOUR machine.
//
//   node check.mjs <address> [--owner] [--json] [--no-link] [--no-7maps] [--token]
//
// Every request goes from this machine straight to the app you name and to public DNS. No
// request ever goes to the app's database (Supabase or Firebase). Nothing about the app is sent to
// 7IT. One exception, and only when the app itself publishes an MCP server: the check
// downloads one small public list from 7Maps (7it.co.il/7maps/known/<2 characters>.json)
// to say whether that server is on the 7Maps map. The request carries only the first two
// characters of a hash, never the address; the comparison happens here. --no-7maps skips
// it. The optional "Full report" link keeps the results in the part of the address after
// "#", which browsers never send to a server.
//
// Plain Node (18 or newer), built-in modules only, no dependencies. Read it top to bottom:
//   1. settings and small helpers        5. the deep checks (owner only)
//   2. the network layer                 6. scoring and the report
//   3. reading the HTML                  7. the text report and the report link
//   4. the public checks                 8. the command line
//
// What it never does: log in, submit a form, write anything anywhere, read data inside the
// app's database (no table names, no counts, no rows, no file listings), download a file it
// found exposed, or keep any key it sees. On the owner's app (the person says the app is
// theirs AND the app carries the ownership token) it names the backend the app's own browser
// code uses and gives the Security Advisor steps the owner follows in their own account.

import { Resolver } from 'node:dns/promises';
import { deflateRawSync } from 'node:zlib';
import { createHash, randomBytes } from 'node:crypto';
import tls from 'node:tls';
import { pathToFileURL } from 'node:url';

// ------------------------------------------------------------------ 1. settings and helpers

export const VERSION = '0.3.1';
const UA = `Mozilla/5.0 (compatible; 7ITGuard/${VERSION}; +https://7it.co.il/tools/guard/)`;
export const REPORT_BASE = 'https://7it.co.il/tools/guard/report/';
export const REVIEW_URL = 'https://7it.co.il/services/ai-built-apps/';
// 7Maps, the public map of MCP servers (also by 7IT). Used only when the app publishes an MCP server.
export const MAPS_KNOWN = 'https://7it.co.il/7maps/known/';
export const MAPS_PAGE = 'https://7it.co.il/7maps/s/';
export const MAPS_CLAIM = 'https://7it.co.il/7maps/claim/';
export const MAPS_SUBMIT = 'https://7it.co.il/7maps/submit/';
const LINK_MAX = 7800; // characters of the encoded report in the link (about 8 KB)

// Polite limits: at most this many requests in flight to one host, and short timeouts.
const PER_HOST = 4;
const TIMEOUT_MS = 12_000;

// Shared platform addresses (myapp.lovable.app): the email check is about the person's own
// domain, so it is skipped there. Same list as the 7IT server.
export const SHARED_APP_HOST = /\.(lovable\.app|lovableproject\.com|replit\.app|repl\.co|replit\.dev|vercel\.app|netlify\.app|pages\.dev|workers\.dev|github\.io|onrender\.com|fly\.dev|herokuapp\.com|web\.app|firebaseapp\.com|azurewebsites\.net|amplifyapp\.com|railway\.app|glitch\.me|vusercontent\.net|bolt\.host|base44\.app|webflow\.io|framer\.app|framer\.website|wixsite\.com|myshopify\.com|bubbleapps\.io|softr\.app|surge\.sh|deno\.dev|streamlit\.app|hf\.space)$/i;

// app.example.com -> example.com; shop.example.co.uk -> example.co.uk
export const mailDomainOf = (host) => {
  const p = host.split('.');
  return p.slice(/\.(co|com|org|net|ac|gov|edu)\.[a-z]{2}$/i.test(host) ? -3 : -2).join('.');
};

// Accepts myapp.com, https://myapp.com/path, http://... Refuses private and local addresses.
export function normalizeTarget(raw) {
  const s = String(raw || '').trim();
  if (!s || s.length > 300) return null;
  try {
    const u = new URL(/^https?:\/\//i.test(s) ? s : `https://${s}`);
    if (!/^https?:$/.test(u.protocol)) return null;
    const h = u.hostname.toLowerCase();
    if (!h.includes('.') || /^[\d.]+$/.test(h) || h.includes(':') || /(^|\.)(localhost|local|internal|lan|test|invalid|example)$/.test(h)) return null;
    u.hash = '';
    u.search = '';
    u.protocol = 'https:';
    return u;
  } catch {
    return null;
  }
}

// The ownership token. Same form and the same two places as the 7IT website's deep scan
// (a meta tag named 7it-site-verification, or a /7it-verify.txt file). The plugin's token is
// derived from the host name alone, so it can be computed here without asking any server;
// the website accepts it too. Any 7it-verify token already on the app also counts.
// The salt keeps its original '7it-shipcheck' spelling on purpose: tokens already on apps stay valid.
export const localToken = (host) => '7it-verify-' + createHash('sha256').update('7it-shipcheck|' + host).digest('hex').slice(0, 28);
const TOKEN_RE = /7it-verify-[0-9a-f]{28}/;

// Run fn over items with at most `limit` running at once.
async function pool(items, limit, fn) {
  const queue = items.slice();
  const out = [];
  await Promise.all(Array.from({ length: Math.min(limit, queue.length) }, async () => {
    for (;;) {
      const item = queue.shift();
      if (item === undefined) break;
      out.push(await fn(item));
    }
  }));
  return out;
}

const kb = (bytes) => Math.round(bytes / 102.4) / 10;
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// ------------------------------------------------------------------ 2. the network layer

// One small HTTP client: follows redirects itself (so it can count them), reads at most
// `max` bytes of a body, and keeps a log of every host it talked to (shown in the report).
export function makeNet({ fetchImpl = globalThis.fetch, timeoutMs = TIMEOUT_MS } = {}) {
  const inFlight = new Map();
  const waiting = new Map();
  const hosts = new Map(); // host -> number of requests
  const acquire = async (host) => {
    if ((inFlight.get(host) || 0) >= PER_HOST) await new Promise((resolve) => { const q = waiting.get(host) || []; q.push(resolve); waiting.set(host, q); });
    inFlight.set(host, (inFlight.get(host) || 0) + 1);
  };
  const release = (host) => {
    inFlight.set(host, (inFlight.get(host) || 1) - 1);
    const q = waiting.get(host);
    if (q && q.length) q.shift()();
  };

  async function readLimited(res, max) {
    if (!res.body || max <= 0) { try { await res.body?.cancel(); } catch { /* ignore */ } return ''; }
    const reader = res.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        size += value.length;
        if (size >= max) { await reader.cancel().catch(() => {}); break; }
      }
    } catch { /* a cut connection keeps what arrived */ }
    const all = new Uint8Array(Math.min(size, max));
    let at = 0;
    for (const c of chunks) { const take = Math.min(c.length, all.length - at); all.set(c.subarray(0, take), at); at += take; if (at >= all.length) break; }
    return new TextDecoder('utf-8', { fatal: false }).decode(all);
  }

  // GET (or HEAD) with manual redirects. Returns { ok, status, url, headers, text, ms, hops, error }.
  async function get(url, { method = 'GET', headers = {}, max = 400_000, follow = true, body } = {}) {
    let current = url;
    let hops = 0;
    const t0 = Date.now();
    for (;;) {
      let host;
      try { host = new URL(current).hostname; } catch { return { ok: false, status: 0, url: current, headers: new Headers(), text: '', ms: 0, hops, error: 'bad_url' }; }
      hosts.set(host, (hosts.get(host) || 0) + 1);
      await acquire(host);
      let res;
      try {
        res = await fetchImpl(current, {
          method,
          body,
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
          headers: { 'User-Agent': UA, 'Accept-Encoding': 'gzip, deflate, br', ...headers },
        });
      } catch (e) {
        release(host);
        const code = String(e?.cause?.code || e?.name || 'error');
        return { ok: false, status: 0, url: current, headers: new Headers(), text: '', ms: Date.now() - t0, hops, error: /ENOTFOUND|EAI_AGAIN/.test(code) ? 'dns' : /Timeout|Abort/i.test(code) ? 'timeout' : /CERT|SSL|TLS/i.test(code) ? 'tls' : 'unreachable' };
      }
      const ms = Date.now() - t0; // time until the headers arrived
      const loc = res.headers.get('location');
      if (follow && res.status >= 300 && res.status < 400 && loc && hops < 6) {
        try { await res.body?.cancel(); } catch { /* ignore */ }
        release(host);
        current = new URL(loc, current).href;
        hops++;
        continue;
      }
      const text = method === 'HEAD' ? '' : await readLimited(res, max);
      release(host);
      return { ok: res.status >= 200 && res.status < 300, status: res.status, url: current, headers: res.headers, text, ms, hops };
    }
  }

  async function json(url, opts = {}) {
    const r = await get(url, { max: 300_000, ...opts });
    let data = null;
    if (r.ok) { try { data = JSON.parse(r.text); } catch { data = null; } }
    return { ...r, json: data };
  }

  return { get, json, hosts };
}

// TLS certificate of the host: days until it expires and who issued it.
export function tlsInfo(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: TIMEOUT_MS }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const reason = socket.authorizationError ? String(socket.authorizationError) : '';
      socket.end();
      if (!cert || !cert.valid_to) return resolve(null);
      const days = Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86_400_000);
      resolve({ days, valid: authorized, reason, issuer: cert.issuer?.O || cert.issuer?.CN || '' });
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

// ------------------------------------------------------------------ 3. reading the HTML

// The attributes of one tag, as a lower-case map.
function attrs(tag) {
  const out = {};
  const rest = tag.replace(/^<\s*[\w:-]+/, '').replace(/\/?>$/, '');
  for (const m of rest.matchAll(/([^\s=<>"'/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
    out[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return out;
}
const textOf = (html) => html.replace(/<script\b[\s\S]*?<\/script>/gi, ' ').replace(/<style\b[\s\S]*?<\/style>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;|&#160;/g, ' ').replace(/\s+/g, ' ').trim();

// Everything the checks need from the home page, read once.
export function readHtml(html, pageUrl) {
  const headEnd = (() => { const i = html.search(/<\/head>/i); return i < 0 ? html.length : i; })();
  const metas = {};
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const a = attrs(m[0]);
    const key = (a.name || a.property || a['http-equiv'] || '').toLowerCase();
    if (key && !(key in metas)) metas[key] = a.content ?? '';
  }
  const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => {
    const a = attrs(m[0]);
    let src = null;
    if (a.src) { try { src = new URL(a.src, pageUrl).href; } catch { src = null; } }
    return { src, inHead: m.index < headEnd, async: 'async' in a, defer: 'defer' in a, module: (a.type || '').toLowerCase() === 'module', ld: /ld\+json/i.test(a.type || '') };
  });
  const linkTags = [...html.matchAll(/<link\b[^>]*>/gi)].map((m) => attrs(m[0]));
  const preloads = linkTags.filter((a) => /modulepreload/i.test(a.rel || '') && a.href).map((a) => { try { return new URL(a.href, pageUrl).href; } catch { return null; } }).filter(Boolean);
  const canonical = (linkTags.find((a) => /(^|\s)canonical(\s|$)/i.test(a.rel || '')) || {}).href || null;
  const htmlTag = attrs((html.match(/<html\b[^>]*>/i) || ['<html>'])[0]);
  const title = ((html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '').replace(/\s+/g, ' ').trim();

  const images = [...html.matchAll(/<img\b[^>]*>/gi)].map((m) => attrs(m[0]));
  const imgNoAlt = images.filter((a) => !('alt' in a) && a.role !== 'presentation' && a['aria-hidden'] !== 'true').length;

  // Form fields: labelled by <label for>, by wrapping <label>, or by aria-label/-labelledby/title.
  const labelFor = new Set([...html.matchAll(/<label\b[^>]*>/gi)].map((m) => attrs(m[0]).for).filter(Boolean));
  const labelSpans = [];
  for (const m of html.matchAll(/<label\b[\s\S]*?<\/label>/gi)) labelSpans.push([m.index, m.index + m[0].length]);
  let fields = 0, unlabeled = 0;
  for (const m of html.matchAll(/<(input|select|textarea)\b[^>]*>/gi)) {
    const a = attrs(m[0]);
    const type = (a.type || '').toLowerCase();
    if (m[1].toLowerCase() === 'input' && /^(hidden|submit|button|reset|image)$/.test(type)) continue;
    fields++;
    const named = a['aria-label'] || a['aria-labelledby'] || a.title || (a.id && labelFor.has(a.id)) || labelSpans.some(([s, e]) => m.index > s && m.index < e);
    if (!named) unlabeled++;
  }
  const hasName = (a, inner) => !!(a['aria-label'] || a['aria-labelledby'] || a.title || textOf(inner) || /<img\b[^>]*\balt\s*=\s*["'][^"']+["']/i.test(inner) || /<title>[^<]+<\/title>/i.test(inner));
  const buttons = [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/gi)];
  const unnamedButtons = buttons.filter((m) => !hasName(attrs('<b ' + m[1] + '>'), m[2])).length;
  const links = [...html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)].filter((m) => /\bhref\s*=/.test(m[1]));
  const unnamedLinks = links.filter((m) => !hasName(attrs('<a ' + m[1] + '>'), m[2])).length;

  const viewport = (metas.viewport || '').toLowerCase();
  const text = textOf(html);
  return {
    title,
    lang: htmlTag.lang || '',
    metas,
    canonical,
    scripts,
    preloads,
    images: images.length,
    imgNoAlt,
    fields,
    unlabeled,
    buttons: buttons.length,
    unnamedButtons,
    links: links.length,
    unnamedLinks,
    zoomDisabled: /user-scalable\s*=\s*(no|0)\b/.test(viewport) || /maximum-scale\s*=\s*1(\.0*)?\b/.test(viewport),
    h1: (html.match(/<h1\b/gi) || []).length,
    main: /<main\b|role\s*=\s*["']main["']/i.test(html),
    textLength: text.length,
    // A page rendered in the browser sends an almost empty shell: the HTML checks see little.
    shell: text.length < 200 && /<div\b[^>]*id\s*=\s*["'](root|app|__next|svelte|q-app)["']/i.test(html),
    mixed: [...html.matchAll(/<(script|link|iframe|img)\b[^>]*(?:src|href)\s*=\s*["']http:\/\/[^"']+["'][^>]*>/gi)].filter((m) => m[1].toLowerCase() !== 'link' || /stylesheet/i.test(m[0])).length,
  };
}

// Where the app runs, from its headers and markup. Used to pick the right fix snippet.
export function stackOf(headers, html) {
  const h = (k) => (headers.get(k) || '').toLowerCase();
  const s = new Set();
  if (h('x-vercel-id') || h('server') === 'vercel') s.add('vercel');
  if (h('x-nf-request-id') || /netlify/.test(h('server'))) s.add('netlify');
  if (h('cf-ray')) s.add('cloudflare');
  if (/nginx/.test(h('server'))) s.add('nginx');
  if (/apache/.test(h('server'))) s.add('apache');
  if (/next\.js/.test(h('x-powered-by')) || /\/_next\/static\//.test(html)) s.add('nextjs');
  if (/<script[^>]+type=["']module["'][^>]+src=["'][^"']*\/assets\/index-[\w-]+\.js/i.test(html)) s.add('vite');
  if (/lovable/i.test(html)) s.add('lovable');
  return [...s];
}

// ------------------------------------------------------------------ 4. the public checks

// Each finding: id, category, severity (critical, high, medium, low, info), a title and one fix.
// Categories, in report order:
export const CATEGORIES = [
  ['security', 'Security'],
  ['data', 'Data exposure'],
  ['secrets', 'Secrets'],
  ['email', 'Email'],
  ['performance', 'Performance'],
  ['accessibility', 'Accessibility'],
  ['seo', 'SEO'],
  ['reliability', 'Reliability'],
];

function headerFindings(headers, add) {
  const get = (k) => headers.get(k);
  const csp = get('content-security-policy');
  const cspRO = get('content-security-policy-report-only');
  if (!csp) {
    if (cspRO) add('csp_report_only', 'security', 'low', 'The Content Security Policy only reports and blocks nothing.', 'Once the reports are clean, send it as Content-Security-Policy instead of Content-Security-Policy-Report-Only.');
    else add('csp_missing', 'security', 'medium', 'No Content Security Policy.', 'Add a Content-Security-Policy header so an injected script cannot run or send your users\' data elsewhere. Start from the policy in the full report and tighten it.');
  } else {
    const scriptSrc = (csp.match(/(?:^|;)\s*script-src\s+([^;]*)/i) || csp.match(/(?:^|;)\s*default-src\s+([^;]*)/i) || [])[1] || '';
    const guarded = /'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(scriptSrc);
    if ((/'unsafe-inline'/.test(scriptSrc) && !guarded) || /(^|\s)\*(\s|$)/.test(scriptSrc) || /'unsafe-eval'/.test(scriptSrc)) {
      add('csp_weak', 'security', 'low', 'The Content Security Policy allows inline or any-origin scripts.', 'Replace \'unsafe-inline\' (and \'unsafe-eval\' or *) in script-src with nonces or hashes, so an injected script is still refused.');
    }
  }
  const hsts = get('strict-transport-security');
  if (!hsts) add('hsts_missing', 'security', 'medium', 'HTTPS is not enforced with HSTS.', 'Send Strict-Transport-Security: max-age=63072000; includeSubDomains so browsers never connect over plain HTTP.');
  else {
    const age = Number((hsts.match(/max-age\s*=\s*(\d+)/i) || [])[1] || 0);
    if (age < 15_552_000) add('hsts_weak', 'security', 'low', `HSTS lasts only ${Math.round(age / 86400)} days.`, 'Raise max-age to at least one year (31536000); two years is the preload standard.');
  }
  if (!get('x-frame-options') && !/frame-ancestors/i.test(csp || '')) add('frame_missing', 'security', 'medium', 'No clickjacking protection.', 'Send X-Frame-Options: DENY (or frame-ancestors \'none\' in the CSP) so the app cannot be framed by another site.');
  if (!/nosniff/i.test(get('x-content-type-options') || '')) add('nosniff_missing', 'security', 'low', 'No X-Content-Type-Options header.', 'Send X-Content-Type-Options: nosniff so the browser never runs a file as a script it was not meant to be.');
  if (!get('referrer-policy')) add('referrer_missing', 'security', 'low', 'No Referrer-Policy header.', 'Send Referrer-Policy: strict-origin-when-cross-origin so private URLs and tokens do not leak to other sites.');
  if (!get('permissions-policy')) add('permissions_missing', 'security', 'low', 'No Permissions-Policy header.', 'Send a Permissions-Policy that turns off the device features the app does not use, for example camera=(), microphone=(), geolocation=().');
  if (!get('cross-origin-opener-policy')) add('coop_missing', 'security', 'low', 'No Cross-Origin-Opener-Policy header.', 'Send Cross-Origin-Opener-Policy: same-origin so other windows cannot reach into the app.');

  // Cookies set on the home page: names only, never values.
  const cookies = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  const insecure = [], noSameSite = [];
  for (const c of cookies) {
    const name = c.split('=')[0].trim().slice(0, 40);
    if (!/;\s*secure/i.test(c)) insecure.push(name);
    if (!/;\s*samesite\s*=/i.test(c)) noSameSite.push(name);
  }
  if (insecure.length) add('cookie_insecure', 'security', 'medium', `${plural(insecure.length, 'cookie')} without the Secure flag (${insecure.slice(0, 3).join(', ')}).`, 'Set Secure on every cookie, and HttpOnly on any cookie that holds a session, so it never travels unencrypted or reaches page scripts.');
  if (noSameSite.length) add('cookie_samesite', 'security', 'low', `${plural(noSameSite.length, 'cookie')} without a SameSite setting (${noSameSite.slice(0, 3).join(', ')}).`, 'Set SameSite=Lax (or Strict) on cookies so other sites cannot send them along with forged requests.');

  const version = [get('server'), get('x-powered-by')].filter(Boolean).find((v) => /\d+\.\d+/.test(v));
  if (version) add('version_leak', 'security', 'low', `The server announces its software version (${version.slice(0, 40)}).`, 'Remove the version from the Server and X-Powered-By headers; it tells attackers which known flaws to try.');
}

// Is a source map served next to one of the first scripts? Reads the first 96 bytes only.
async function sourceMapCheck(net, scripts, add) {
  for (const src of scripts.slice(0, 3)) {
    const r = await net.get(src + '.map', { headers: { Range: 'bytes=0-96' }, max: 96 });
    if ((r.status === 200 || r.status === 206) && /"version"|"mappings"|"sources"/.test(r.text)) {
      add('sourcemap_public', 'secrets', 'high', `A JavaScript source map is public (${new URL(src).pathname}.map).`, 'Stop publishing .map files in production (for Vite: build.sourcemap false; for Next.js: productionBrowserSourceMaps false), so nobody can rebuild your original source and any key written in it.');
      return true;
    }
  }
  return false;
}

async function performanceChecks(net, home, page, firstParty, add, metrics) {
  metrics.ttfb_ms = home.ms;
  metrics.html_kb = kb(home.text.length);
  metrics.scripts = page.scripts.filter((s) => s.src).length;
  metrics.compression = (home.headers.get('content-encoding') || 'none').toLowerCase();
  if (home.ms > 1800) add('slow_ttfb', 'performance', 'medium', `The server took ${(home.ms / 1000).toFixed(1)} s to start answering.`, 'Cache the home page at the edge (static or ISR), or find the slow database call or cold start behind it.');
  else if (home.ms > 800) add('slow_ttfb', 'performance', 'low', `The server took ${(home.ms / 1000).toFixed(1)} s to start answering.`, 'Aim for under 0.8 s: cache the page at the edge or make the first database call faster.');
  if (home.text.length > 500_000) add('html_heavy', 'performance', 'medium', `The home page HTML weighs ${Math.round(home.text.length / 1024)} KB.`, 'Move inlined data and SVGs out of the HTML, and send only what the first screen needs.');
  else if (home.text.length > 150_000) add('html_heavy', 'performance', 'low', `The home page HTML weighs ${Math.round(home.text.length / 1024)} KB.`, 'Trim inlined data, styles and SVGs from the HTML.');
  if (metrics.compression === 'none' && home.text.length > 10_000) add('no_compression', 'performance', 'medium', 'The HTML is sent without compression.', 'Turn on gzip or Brotli on the server or CDN; text shrinks by 70 to 80 percent.');

  // Script weight: one HEAD request per first-party script (up to 12), for size and caching.
  const heads = await pool(firstParty.slice(0, 12), 3, async (src) => {
    let r = await net.get(src, { method: 'HEAD' });
    if (!r.ok) r = await net.get(src, { headers: { Range: 'bytes=0-0' }, max: 1 });
    const size = Number(r.headers.get('content-length') || (r.headers.get('content-range') || '').split('/')[1] || 0);
    return { src, size: Number.isFinite(size) ? size : 0, cache: r.headers.get('cache-control') || '', encoding: r.headers.get('content-encoding') || '' };
  });
  const total = heads.reduce((s, h) => s + h.size, 0);
  metrics.js_kb = Math.round(total / 1024);
  if (total > 1_000_000) add('js_heavy', 'performance', 'medium', `The page loads about ${Math.round(total / 1024)} KB of its own JavaScript (compressed).`, 'Split the bundle by route, load heavy libraries only where they are used, and drop unused dependencies.');
  else if (total > 500_000) add('js_heavy', 'performance', 'low', `The page loads about ${Math.round(total / 1024)} KB of its own JavaScript (compressed).`, 'Split the bundle by route and lazy-load what the first screen does not need.');
  if (metrics.scripts > 20) add('many_scripts', 'performance', 'low', `The page loads ${metrics.scripts} separate scripts.`, 'Bundle or defer third-party scripts; each one costs a request and main-thread time on a phone.');
  const blocking = page.scripts.filter((s) => s.src && s.inHead && !s.async && !s.defer && !s.module).length;
  metrics.render_blocking = blocking;
  if (blocking > 0) add('render_blocking', 'performance', 'low', `${plural(blocking, 'script')} in the head ${blocking === 1 ? 'blocks' : 'block'} the first paint.`, 'Add defer (or async for independent scripts) to scripts in the head.');
  const hashed = heads.filter((h) => /[.-][a-z0-9_-]{8,}\.m?js(\?|$)/i.test(h.src));
  const weak = hashed.filter((h) => { const age = Number((h.cache.match(/max-age=(\d+)/) || [])[1] || 0); return age < 86_400 * 30; });
  if (hashed.length && weak.length === hashed.length) add('weak_caching', 'performance', 'low', 'Versioned script files are not cached for long.', 'Serve files with a content hash in the name with Cache-Control: public, max-age=31536000, immutable.');
}

function accessibilityChecks(page, add, metrics) {
  metrics.images = page.images;
  metrics.images_no_alt = page.imgNoAlt;
  metrics.fields = page.fields;
  metrics.fields_unlabeled = page.unlabeled;
  if (!page.lang) add('no_lang', 'accessibility', 'medium', 'The page does not declare its language.', 'Add lang="en" (or the right language) to the <html> tag so screen readers pronounce it correctly.');
  if (page.imgNoAlt) add('img_alt', 'accessibility', 'medium', `${page.imgNoAlt} of ${plural(page.images, 'image')} ${page.imgNoAlt === 1 ? 'has' : 'have'} no text alternative.`, 'Give every meaningful image an alt text, and decorative ones alt="".');
  if (page.unlabeled) add('unlabeled_inputs', 'accessibility', 'medium', `${page.unlabeled} of ${plural(page.fields, 'form field')} ${page.unlabeled === 1 ? 'has' : 'have'} no label.`, 'Connect a <label for> to each field (a placeholder is not a label).');
  if (page.unnamedButtons) add('unnamed_buttons', 'accessibility', 'low', `${plural(page.unnamedButtons, 'button')} with no readable name.`, 'Give icon buttons an aria-label that says what they do.');
  if (page.unnamedLinks) add('unnamed_links', 'accessibility', 'low', `${plural(page.unnamedLinks, 'link')} with no readable name.`, 'Give icon links an aria-label or visible text.');
  if (page.zoomDisabled) add('zoom_disabled', 'accessibility', 'medium', 'Zoom is turned off on phones.', 'Remove user-scalable=no and maximum-scale=1 from the viewport meta tag.');
  if (!page.shell && !page.h1) add('no_h1', 'accessibility', 'low', 'The page has no main heading (h1).', 'Give each page one h1 that says what it is.');
  if (!page.shell && !page.main) add('no_main', 'accessibility', 'low', 'The page has no main landmark.', 'Wrap the page content in <main> so keyboard and screen reader users can jump to it.');
}

async function seoChecks(net, origin, home, page, add, metrics) {
  if (!page.title) add('no_title', 'seo', 'medium', 'The page has no title.', 'Add a <title> of 30 to 60 characters that says what the app does.');
  else if (page.title.length < 10 || page.title.length > 65) add('title_length', 'seo', 'low', `The title is ${page.title.length} characters long.`, 'Keep the title between 30 and 60 characters so search results show it whole.');
  if (!page.metas.description) add('no_description', 'seo', 'low', 'No meta description.', 'Add a meta description of 70 to 160 characters; search engines and link previews show it.');
  if (!page.canonical) add('no_canonical', 'seo', 'low', 'No canonical link.', 'Add <link rel="canonical" href="..."> so duplicates (www, trailing slash, tracking parameters) count as one page.');
  if (!page.metas['og:title'] || !page.metas['og:image']) add('no_og', 'seo', 'low', 'No Open Graph title or image.', 'Add og:title, og:description and og:image so links to the app show a proper preview.');
  const robotsMeta = `${page.metas.robots || ''} ${home.headers.get('x-robots-tag') || ''}`.toLowerCase();
  if (/noindex/.test(robotsMeta)) add('noindex', 'seo', 'high', 'The page tells search engines not to index it (noindex).', 'Remove noindex from the robots meta tag or X-Robots-Tag header before launch, unless the app is meant to stay out of search.');

  const robots = await net.get(origin + '/robots.txt', { max: 100_000 });
  const robotsText = robots.ok && !/<html/i.test(robots.text) ? robots.text : '';
  metrics.robots_txt = !!robotsText;
  if (!robotsText) add('no_robots', 'seo', 'low', 'No robots.txt.', 'Publish a robots.txt that allows crawling and names the sitemap.');
  else {
    // A "User-agent: *" group that disallows the whole site.
    let star = false, blocksAll = false;
    for (const raw of robotsText.split(/\r?\n/)) {
      const line = raw.replace(/#.*/, '').trim();
      const m = line.match(/^([a-z-]+)\s*:\s*(.*)$/i);
      if (!m) continue;
      if (/^user-agent$/i.test(m[1])) star = m[2].trim() === '*';
      else if (star && /^disallow$/i.test(m[1]) && m[2].trim() === '/') blocksAll = true;
    }
    if (blocksAll) add('robots_blocks_all', 'seo', 'high', 'robots.txt blocks every crawler from the whole site.', 'Change "Disallow: /" under "User-agent: *" before launch, unless the app must stay out of search.');
  }
  const sitemapUrl = ((robotsText.match(/^\s*sitemap\s*:\s*(\S+)/im) || [])[1]) || origin + '/sitemap.xml';
  let sitemap = false;
  try {
    const sm = await net.get(new URL(sitemapUrl, origin).href, { max: 2000 });
    sitemap = sm.ok && /<(urlset|sitemapindex)\b/i.test(sm.text);
  } catch { sitemap = false; }
  metrics.sitemap = sitemap;
  if (!sitemap) add('no_sitemap', 'seo', 'low', 'No sitemap found.', 'Publish /sitemap.xml with every public page and name it in robots.txt.');
}

async function reliabilityChecks(net, ctx, home, add, metrics) {
  const { host, origin } = ctx;
  metrics.redirects = home.hops;
  if (home.hops > 2) add('long_redirects', 'reliability', 'low', `The address goes through ${home.hops} redirects before the page.`, 'Point links and DNS at the final address so visitors land in one hop.');
  const cert = await ctx.tls(host).catch(() => null);
  if (cert) {
    metrics.cert_days = cert.days;
    if (!cert.valid) add('cert_invalid', 'reliability', 'critical', `Browsers do not trust the HTTPS certificate (${cert.reason || 'invalid'}).`, 'Issue a certificate from a trusted authority for this exact host name (most hosts do it automatically once the domain is connected).');
    else if (cert.days < 7) add('cert_expiring', 'reliability', 'high', `The HTTPS certificate expires in ${cert.days} days.`, 'Renew it now and check that automatic renewal works.');
    else if (cert.days < 14) add('cert_expiring', 'reliability', 'medium', `The HTTPS certificate expires in ${cert.days} days.`, 'Automatic renewal usually runs about 30 days before expiry; check that it is on and working.');
  }
  // An address that does not exist should answer 404, not the home page.
  const missing = await net.get(`${origin}/7it-guard-${randomBytes(4).toString('hex')}`, { max: 2000 });
  metrics.not_found_status = missing.status;
  if (missing.status === 200) add('soft_404', 'reliability', 'low', 'Missing pages answer 200 instead of 404.', 'Return a real 404 status for unknown addresses so search engines and monitors can tell an error from a page.');
  // www and the bare domain: both should answer (one redirecting to the other).
  const bare = host.replace(/^www\./, '');
  if (!SHARED_APP_HOST.test(host) && bare === mailDomainOf(host) && (host === bare || host === 'www.' + bare)) {
    const alt = host === bare ? 'www.' + bare : bare;
    const r = await net.get(`https://${alt}/`, { follow: false, max: 0 });
    metrics.alt_host = alt;
    metrics.alt_host_status = r.status;
    if (r.status === 0) add('alt_host_down', 'reliability', 'low', `${alt} does not answer over HTTPS.`, `Point ${alt} at the app and redirect it to ${host}, so people who type it still arrive.`);
  }
  const sec = await net.get(`${origin}/.well-known/security.txt`, { max: 2000 });
  if (!(sec.ok && /contact\s*:/i.test(sec.text))) add('security_txt_missing', 'security', 'info', 'No security.txt.', 'Publish /.well-known/security.txt with a contact, so someone who finds a flaw can tell you.');
}

// Does the app publish an MCP server (a server AI agents connect to)? Read from three public
// places on the app itself: its MCP server card (/.well-known/mcp/server-card.json), its AI
// catalog (/.well-known/ai-catalog.json, following up to 3 server cards on the same host) and
// /mcp. Only the server addresses are kept. A single-page app that answers every path with its
// home page does not count, and neither does any page that is not an MCP answer.
export async function mcpFind(net, origin, homeText) {
  const host = new URL(origin).hostname;
  const found = new Set();
  const sameAsHome = (r) => !!homeText && r.text.slice(0, 1500) === homeText.slice(0, 1500);
  const addUrl = (raw) => {
    try {
      const u = new URL(raw, origin);
      if (u.protocol === 'https:' && found.size < 5) found.add(u.origin + u.pathname.replace(/\/+$/, ''));
    } catch { /* not an address */ }
  };
  const fromCard = (j) => { for (const r of Array.isArray(j?.remotes) ? j.remotes : []) if (r && typeof r.url === 'string') addUrl(r.url); };
  const readJson = (r) => { if (!r.ok || sameAsHome(r)) return null; try { return JSON.parse(r.text); } catch { return null; } };

  const [card, catalog, endpoint] = await Promise.all([
    net.get(`${origin}/.well-known/mcp/server-card.json`, { max: 100_000, headers: { Accept: 'application/json' } }),
    net.get(`${origin}/.well-known/ai-catalog.json`, { max: 100_000, headers: { Accept: 'application/json' } }),
    net.get(`${origin}/mcp`, { max: 4000, follow: false, headers: { Accept: 'application/json, text/event-stream' } }),
  ]);
  fromCard(readJson(card));
  const cat = readJson(catalog);
  const cards = (Array.isArray(cat?.entries) ? cat.entries : [])
    .filter((e) => e && typeof e.url === 'string' && /mcp/i.test(String(e.type || '')))
    .map((e) => { try { return new URL(e.url, origin); } catch { return null; } })
    .filter((u) => u && u.hostname === host && u.protocol === 'https:')
    .slice(0, 3);
  for (const u of cards) fromCard(readJson(await net.get(u.href, { max: 100_000, headers: { Accept: 'application/json' } })));
  // /mcp itself: a JSON-RPC answer, an event stream, or a sign-in request that names its OAuth metadata.
  const ctype = endpoint.headers.get('content-type') || '';
  const auth = endpoint.headers.get('www-authenticate') || '';
  if (endpoint.status && !sameAsHome(endpoint) && (/"jsonrpc"\s*:\s*"2\.0"/.test(endpoint.text) || /text\/event-stream/i.test(ctype) || (endpoint.status === 401 && /resource_metadata=/i.test(auth)))) addUrl(`${origin}/mcp`);
  return [...found];
}

// The map key and hash of a server address, exactly as 7Maps states them in its public lists:
// host in lower case without "www." and port, then the path without trailing "/"; SHA-256, first 12 hex.
export const mapsKey = (raw) => {
  try {
    const u = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
    return u.hostname.toLowerCase().replace(/^www\./, '') + (u.pathname.replace(/\/+$/, '') || '');
  } catch { return ''; }
};
export const mapsHash = (key) => createHash('sha256').update(key, 'utf8').digest('hex').slice(0, 12);

// Is each server on 7Maps? Downloads the public list for the first two characters of each hash
// (about 1 KB; at most 3 downloads) and compares here. The address never leaves this machine.
export async function mapsLookup(net, urls) {
  const out = urls.map((url) => ({ url, key: mapsKey(url), on_7maps: null }));
  const buckets = new Map();
  for (const s of out) { if (!s.key) continue; s.hash = mapsHash(s.key); const b = s.hash.slice(0, 2); if (!buckets.has(b)) buckets.set(b, null); }
  for (const b of [...buckets.keys()].slice(0, 3)) {
    const r = await net.json(`${MAPS_KNOWN}${b}.json?via=guard`, { headers: { Accept: 'application/json' }, max: 100_000 });
    if (r.json && Array.isArray(r.json.hashes)) buckets.set(b, new Set(r.json.hashes));
  }
  for (const s of out) {
    const set = s.hash ? buckets.get(s.hash.slice(0, 2)) : null;
    if (set) s.on_7maps = set.has(s.hash);
    s.page = s.on_7maps ? MAPS_PAGE + s.key : null;
    delete s.hash;
  }
  return out;
}

// SPF, DKIM, DMARC of the app's domain from public DNS (no mail is sent).
const SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 'kl', 'kl2', 's1', 's2', 'mandrill', 'mxvault', 'default', 'dkim', 'smtp', 'sm', 'shopify', 'sendgrid', 'em', 'pm', 'mte1', 'zendesk1', 'cm', 'hs1', 'hs2', 'resend', 'mailgun', 'amazonses'];
export async function emailCheck(domain, dns) {
  const txt = async (n) => { try { return (await dns.resolveTxt(n)).map((r) => r.join('')); } catch { return []; } };
  const cname = async (n) => { try { return await dns.resolveCname(n); } catch { return []; } };
  const [rootTxt, dmarcTxt, mxs] = await Promise.all([txt(domain), txt(`_dmarc.${domain}`), dns.resolveMx(domain).catch(() => [])]);
  const spf = rootTxt.filter((t) => /^v=spf1\b/i.test(t));
  const dmarc = dmarcTxt.find((t) => /^v=DMARC1\b/i.test(t)) || null;
  const tag = (k) => (dmarc?.match(new RegExp(`(?:^|;)\\s*${k}\\s*=\\s*([^;]+)`, 'i')) || [])[1]?.trim().toLowerCase() || null;
  const dkim = [];
  await pool(SELECTORS, 8, async (s) => {
    const n = `${s}._domainkey.${domain}`;
    const [t, c] = await Promise.all([txt(n), cname(n)]);
    if (t.some((x) => /p=/i.test(x)) || c.length) dkim.push(s);
  });
  const all = spf[0]?.match(/([~?+-])all\b/i)?.[1] || (spf[0] && /\ball\b/i.test(spf[0]) ? '+' : null);
  const policy = tag('p');
  const pct = tag('pct') ? Number(tag('pct')) : null;
  return {
    domain, mx: mxs.length > 0, spf: spf.length === 1, spf_multiple: spf.length > 1, spf_all: all,
    dmarc: !!dmarc, dmarc_policy: policy, dmarc_pct: pct, dmarc_reports: !!tag('rua'),
    dmarc_enforced: !!dmarc && (policy === 'quarantine' || policy === 'reject') && (pct == null || pct === 100),
    dkim: dkim.sort(),
  };
}
function emailFindings(m, add) {
  const d = m.domain;
  if (!m.mx && !m.dmarc_enforced) {
    add('no_mail_lockdown', 'email', m.dmarc ? 'low' : 'medium', `Anyone can send email that claims to come from ${d}.`, `${d} receives no mail. If it sends none either, publish "v=spf1 -all" and a DMARC record "v=DMARC1; p=reject" so nobody can send as it.`);
    return;
  }
  if (!m.spf && !m.spf_multiple) add('no_spf', 'email', 'high', `${d} has no SPF record.`, `Publish one SPF record on ${d} that lists every service sending its mail, ending in -all or ~all.`);
  if (m.spf_multiple) add('spf_multiple', 'email', 'high', `${d} has more than one SPF record.`, 'Merge them into a single record; two records make SPF fail for every message.');
  if (m.spf_all === '+') add('spf_pass_all', 'email', 'high', 'The SPF record ends in +all, which lets anyone send as the domain.', 'End it in -all or ~all.');
  if (!m.dmarc) add('no_dmarc', 'email', 'medium', `${d} has no DMARC record, so mail can be spoofed and can land in spam.`, `Publish "v=DMARC1; p=none; rua=mailto:dmarc@${d}" at _dmarc.${d}, read the reports, then move to p=quarantine and p=reject.`);
  else if (!m.dmarc_enforced) add('dmarc_not_enforced', 'email', 'low', `DMARC is set to ${m.dmarc_policy || 'none'}, so spoofed mail is still delivered.`, 'When the reports show every real sender passing, move to p=quarantine, then p=reject.');
  if (!m.dkim.length) add('no_dkim', 'email', 'low', 'No DKIM key found under the common selectors.', 'Turn on DKIM signing in the service that sends your mail and publish the record it gives you. (A key under an unusual selector cannot be seen from outside.)');
  if (m.dmarc && !m.dmarc_reports) add('no_dmarc_reports', 'email', 'low', 'DMARC sends its reports nowhere.', 'Add rua=mailto:... to the DMARC record to see who sends mail as your domain.');
}

// Google PageSpeed, only with the person's OWN key in PAGESPEED_API_KEY (the request goes to Google).
async function pageSpeed(net, url, key, add, metrics) {
  const q = new URLSearchParams({ url, strategy: 'mobile', key });
  q.append('category', 'performance');
  q.append('category', 'accessibility');
  const r = await net.json(`https://www.googleapis.com/pagespeedonline/v5/runPagespeed?${q}`, {});
  const cats = r.json?.lighthouseResult?.categories;
  if (!cats) { metrics.pagespeed = 'failed'; return; }
  const perf = typeof cats.performance?.score === 'number' ? Math.round(cats.performance.score * 100) : null;
  const acc = typeof cats.accessibility?.score === 'number' ? Math.round(cats.accessibility.score * 100) : null;
  metrics.pagespeed = { performance: perf, accessibility: acc };
  if (perf != null && perf < 90) add('psi_performance', 'performance', perf < 50 ? 'medium' : 'low', `Google PageSpeed on a phone: ${perf}/100.`, 'Start with the largest items in the PageSpeed report: images, unused JavaScript and render-blocking resources.');
  if (acc != null && acc < 90) add('psi_accessibility', 'accessibility', acc < 80 ? 'medium' : 'low', `Lighthouse accessibility: ${acc}/100.`, 'Fix the failing Lighthouse rules, then test with a keyboard and a screen reader.');
}

// ------------------------------------------------------------------ 5. the deep checks (owner only)

// Is the ownership token on the app? Home page meta tag (already fetched) or /7it-verify.txt.
async function ownershipToken(net, origin, html) {
  const meta = [...html.matchAll(/<meta\b[^>]*>/gi)].map((m) => attrs(m[0])).find((a) => (a.name || '').toLowerCase() === '7it-site-verification');
  if (meta && TOKEN_RE.test(meta.content || '')) return 'meta';
  const file = await net.get(`${origin}/7it-verify.txt`, { max: 200 });
  return file.ok && TOKEN_RE.test(file.text) ? 'file' : null;
}

// A MetaMCP session list (CVE-2026-79537): JSON that names live sessions, by session id or
// with the namespaces they are connected to. A health answer without sessions, an HTML page
// or an empty list is not a match. Only this one path is read; /mcp-proxy/ is never touched.
export function mcpSessionsShape(b) {
  const t = String(b || '').trim();
  if (!/^[[{]/.test(t)) return false;
  if (!/"(?:sessions?|session_?ids?|active_?sessions)"\s*:/i.test(t)) return false;
  return /"namespace(?:s|_?ids?|_?uuids?|_?names?)?"\s*:/i.test(t)
    || /"session_?id"\s*:\s*"[^"\s]{8,}"/i.test(t)
    || /"(?:sessions?|session_?ids?|active_?sessions)"\s*:\s*\[\s*"[^"\s]{8,}"/i.test(t)
    || /"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"/i.test(t);
}

// Well-known files that should never be public. Each matches only on the SHAPE of the
// sensitive file (an env file has NAME=value lines), reads at most 4 KB, keeps nothing,
// and reports the path only.
const PROBES = [
  ['/.env', 'env', 'critical', (b) => /^[A-Za-z_][A-Za-z0-9_]*=/m.test(b)],
  ['/.env.local', 'env', 'critical', (b) => /^[A-Za-z_][A-Za-z0-9_]*=/m.test(b)],
  ['/.env.production', 'env', 'critical', (b) => /^[A-Za-z_][A-Za-z0-9_]*=/m.test(b)],
  ['/.env.development', 'env', 'critical', (b) => /^[A-Za-z_][A-Za-z0-9_]*=/m.test(b)],
  ['/.git/HEAD', 'git', 'high', (b) => /^ref:\s/.test(b.trim()) || /^[0-9a-f]{40}$/.test(b.trim())],
  ['/.git/config', 'git', 'high', (b) => /\[core\]/.test(b)],
  ['/backup.sql', 'backup', 'critical', (b) => /CREATE TABLE|INSERT INTO/i.test(b)],
  ['/dump.sql', 'backup', 'critical', (b) => /CREATE TABLE|INSERT INTO/i.test(b)],
  ['/database.sql', 'backup', 'critical', (b) => /CREATE TABLE|INSERT INTO/i.test(b)],
  ['/backup.zip', 'backup', 'high', (b) => b.startsWith('PK')],
  ['/.npmrc', 'env', 'high', (b) => /_authToken\s*=/.test(b)],
  ['/.DS_Store', 'ds_store', 'low', (b) => b.includes('Bud1')],
  ['/phpinfo.php', 'phpinfo', 'high', (b) => /phpinfo\(\)|PHP Version \d/.test(b)],
  ['/server-status', 'server_status', 'medium', (b) => /Apache Server Status/i.test(b)],
  ['/adminer.php', 'db_admin', 'high', (b) => /adminer/i.test(b) && /password/i.test(b)],
  ['/phpmyadmin/', 'db_admin', 'high', (b) => /phpMyAdmin/.test(b)],
  ['/metamcp/health/sessions', 'mcp_sessions', 'critical', mcpSessionsShape],
];
const PROBE_TEXT = {
  env: ['An environment file is public', 'Stop serving it (keep secrets in the host\'s environment settings, never in the web root) and rotate every key it contained.'],
  git: ['The Git repository is public', 'Remove the .git folder from what the server publishes; the full source history may be downloadable.'],
  backup: ['A backup file is public', 'Delete it from the web root and treat whatever it held as exposed.'],
  ds_store: ['A .DS_Store file lists your folders', 'Delete it and stop uploading .DS_Store files.'],
  phpinfo: ['A phpinfo page shows the server\'s configuration', 'Delete the page.'],
  server_status: ['The Apache status page is public', 'Restrict /server-status to localhost.'],
  db_admin: ['A database admin tool is public', 'Remove it or put it behind a VPN or IP allowlist.'],
  mcp_sessions: ['Anyone can see the live sessions of your MCP gateway (MetaMCP)', 'Block /mcp-proxy/ and this address at your reverse proxy, turn off open sign-up, keep the gateway off the public internet (VPN or private network only), and rotate every key and password it holds.'],
};
async function exposedFiles(net, origin, homeHtml, add) {
  const homeStart = homeHtml.slice(0, 300);
  await pool(PROBES, 3, async ([path, kind, sev, match]) => {
    const r = await net.get(origin + path, { headers: { Range: 'bytes=0-4095' }, max: 4096, follow: false });
    if (!(r.status === 200 || r.status === 206)) return;
    if (r.text.slice(0, 300) === homeStart) return; // the app answered with its home page (single-page app)
    if (!match(r.text)) return;
    const [title, fix] = PROBE_TEXT[kind];
    add('exposed_' + kind, 'data', sev, `${title} at ${path}.`, fix);
  });
  if (/<title>\s*(Index of|Directory listing)/i.test(homeHtml)) add('exposed_dirlist', 'data', 'medium', 'Directory listing is on.', 'Turn off automatic directory listing on the host.');
}

// The text the app ships to browsers: the home page plus up to 8 of its own scripts.
async function clientText(net, home, page) {
  const own = [...page.scripts.map((s) => s.src), ...page.preloads].filter(Boolean).filter((u, i, a) => a.indexOf(u) === i && /\.m?js(\?|$)/i.test(u) && !/googletagmanager|google-analytics|gstatic|jsdelivr|unpkg|cdnjs/i.test(u));
  const files = [{ path: '/', text: home.text }];
  const bodies = await pool(own.slice(0, 8), 3, async (u) => ({ path: new URL(u).pathname, text: (await net.get(u, { max: 1_500_000 })).text }));
  return files.concat(bodies);
}

// Secret key shapes that must never reach a browser. Each is matched and reported as a TYPE
// and the FILE it is in. The value is never printed, stored or sent anywhere.
const SECRET_SHAPES = [
  ['openai', 'an OpenAI secret key', 'critical', /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/],
  ['anthropic', 'an Anthropic API key', 'critical', /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/],
  ['stripe', 'a Stripe live secret key', 'critical', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/],
  ['github', 'a GitHub token', 'critical', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/],
  ['sendgrid', 'a SendGrid API key', 'critical', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/],
  ['private_key', 'a private key', 'critical', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ['google_sa', 'a Google service account file', 'critical', /"type"\s*:\s*"service_account"/],
  ['aws', 'an AWS access key id', 'high', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['slack', 'a Slack token', 'high', /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
  ['twilio', 'a Twilio API key', 'high', /\bSK[0-9a-f]{32}\b/],
  ['mailgun', 'a Mailgun API key', 'high', /\bkey-[0-9a-f]{32}\b/],
  ['resend', 'a Resend API key', 'high', /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b/],
];
function decodeJwtPayload(jwt) {
  try { return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8')); } catch { return null; }
}
function secretScan(files, add) {
  const seen = new Set();
  for (const { path, text } of files) {
    for (const [id, label, sev, re] of SECRET_SHAPES) {
      if (seen.has(id) || !re.test(text)) continue;
      seen.add(id);
      add('secret_' + id, 'secrets', sev, `Something shaped like ${label} is in the code sent to browsers (${path}).`, 'Rotate it now in that service, move the call that needs it to a server function, and keep the key in server-side environment variables only.');
    }
  }
}

// The backend behind the app: PASSIVE ONLY. 7IT never reads data inside a customer's database.
// The check sends no request at all to the app's Supabase or Firebase project: no table names, no
// counts, no settings, no bucket or file listings. It reads only the code the app already sends to
// every visitor (the home page and its own scripts, fetched above), notes which backend that code
// names, and looks for secret key shapes there. A secret is reported by its KIND only; the matched
// text never leaves the function that tests it. Whether a table is readable by anyone is answered
// by the owner, inside their own Supabase account, with the Security Advisor steps below (the same
// plain-words flow and AI builder prompt as 7it.co.il/tools/supabase-check/).

const SB_REF_RE = /\bhttps?:\/\/([a-z0-9]{20})\.supabase\.(?:co|in)\b/;
// Signs of the Supabase client when the project sits behind a custom domain.
const SB_LIB_RE = /GoTrueClient|\bsb_publishable_[A-Za-z0-9_-]{10,}|supabase-js/;
const SB_JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
// The new-style secret key (the publishable sb_publishable_ key is meant for browsers and is not matched).
const SB_SECRET_RE = /\bsb_secret_[A-Za-z0-9_-]{20,}/;
// A Postgres connection address to a Supabase database that carries a real password (placeholders
// such as [YOUR-PASSWORD] are not a password).
const SB_DB_URL_RE = /\bpostgres(?:ql)?:\/\/[^\s"'`:@/]{1,80}:([^\s"'`@/]{6,200})@[A-Za-z0-9.-]{0,120}supabase\.(?:co|com|in)\b/g;

// Does the text name a Supabase project, and which secret KINDS does it carry? Returns the project
// ref (public: it is the project's own address, used only for the owner's dashboard links) and kind
// names; never a key.
export function supabaseIn(text) {
  const t = String(text || '');
  let ref = (SB_REF_RE.exec(t) || [])[1] || null;
  let found = !!ref;
  const kinds = new Set();
  for (const m of t.matchAll(SB_JWT_RE)) {
    const p = decodeJwtPayload(m[0]);
    if (!p) continue;
    if (p.role === 'service_role') kinds.add('service_role');
    if (p.iss === 'supabase') { found = true; if (!ref && typeof p.ref === 'string' && /^[a-z0-9]{20}$/.test(p.ref)) ref = p.ref; }
  }
  if (SB_SECRET_RE.test(t)) kinds.add('sb_secret');
  for (const m of t.matchAll(SB_DB_URL_RE)) if (!/[[\]<>{}]|password|your-?pass/i.test(m[1])) { kinds.add('db_url'); break; }
  if (!found && (SB_LIB_RE.test(t) || kinds.size)) found = true;
  return { found, ref, secrets: ['service_role', 'sb_secret', 'db_url'].filter((k) => kinds.has(k)) };
}

const SB_DASH = (ref, page) => `https://supabase.com/dashboard/project/${ref || '_'}/${page}`;
const SB_SECRET_TEXT = {
  service_role: ['secret_sb_service', 'The Supabase service role key is in the code sent to browsers.'],
  sb_secret: ['secret_sb_secret', 'A Supabase secret key (sb_secret_) is in the code sent to browsers.'],
  db_url: ['secret_sb_db_url', 'A Supabase database password, inside a connection address, is in the code sent to browsers.'],
};
// The AI builder prompts: the same text as the site's self-help entries supabase_rls and
// supabase_secret_key (7IT-LANDING data/guard-selfhelp/catalog.json), with the app's address filled in.
export const SB_RLS_PROMPT = 'My app {site} uses Supabase. Turn on Row Level Security for every table in the public schema. For each table, add policies so a signed-in user can select, insert, update and delete only their own rows (compare auth.uid() with the owner column, usually user_id). A table that is meant to be public gets a select-only policy and no write access. Never use the service role key or any secret key in browser code. Then fix each warning the Supabase Security Advisor lists. Write the changes as a migration and show me the SQL before you apply it. Do not delete any data. Do not change anything unrelated. When you are done, tell me in plain words what you changed.';
export const SB_SECRET_PROMPT = 'A Supabase secret (the service role key, an sb_secret_ key or the database password) is in the code that {site} sends to browsers. Remove it from every file sent to the browser. Move any code that needs it to a server function or a Supabase Edge Function that reads it from a server-side environment variable. The browser keeps only the publishable or anon key. I will create the new key myself; use it only on the server. Do not delete any data. Do not change anything unrelated. When you are done, tell me in plain words what you changed.';
export const SB_NEVER_READS = 'This check never reads your data.';

// The guided Security Advisor step, in plain words (the supabase_rls flow), for the text report and --json.
export function supabaseGuide(host, sb) {
  const advisor = SB_DASH(sb.ref, 'advisors/security');
  const guide = {
    never_reads: SB_NEVER_READS,
    title: 'Make sure your Supabase data is not readable by anyone',
    means: 'If a table has no row rules, anyone with your public key can read it.',
    advisor_url: advisor,
    steps: [
      `Open your Supabase project, then Advisors, then Security Advisor (${advisor}). If it lists no security warnings, you are done.`,
      'Copy the prompt below into your AI builder. It turns on Row Level Security and owner-only rules.',
      'Run the Security Advisor again. Check that each warning is gone.',
      'If warnings are still listed, paste them into your AI builder, under the same prompt.',
    ],
    ai_prompt: SB_RLS_PROMPT.replace('{site}', host),
  };
  if (sb.secrets.length) {
    guide.secret_steps = [
      `In Supabase, open Project Settings and its keys page (${SB_DASH(sb.ref, 'settings/api-keys')}). Create a new secret key and delete the exposed one. For a database password: Project Settings, then Database, and reset the password.`,
      'Ask your AI builder to move it out of browser code, to the server, with the secret key prompt.',
      'Then check your data rules with the Security Advisor steps.',
    ];
    guide.secret_prompt = SB_SECRET_PROMPT.replace('{site}', host);
  }
  return guide;
}

function supabaseCheck(host, text, add, info) {
  const sb = supabaseIn(text);
  if (!sb.found) return;
  for (const kind of sb.secrets) {
    const [id, title] = SB_SECRET_TEXT[kind];
    add(id, 'secrets', 'critical', title, `Anyone can copy it and read or change all your data, past every rule. Rotate it in your Supabase dashboard (${SB_DASH(sb.ref, 'settings/api-keys')}), then have your AI builder move the code that needs it to the server (the prompt is below the list). Removing it from the code does not undo the exposure.`);
  }
  add('sb_advisor', 'data', 'medium', 'This app uses Supabase: make sure no table is readable by anyone.', `If a table has no row rules, anyone with your public key can read it. Open the Security Advisor in your own Supabase account (${SB_DASH(sb.ref, 'advisors/security')}) and follow the steps below the list. ${SB_NEVER_READS}`);
  info.supabase = { found: true, project: sb.ref, secrets: sb.secrets, guide: supabaseGuide(host, sb) };
}

// Firebase: also passive. The web config is public by design; the protection is in the Security
// Rules, which the owner checks in their own Firebase console. No request goes to the project.
function firebaseCheck(text, add, info) {
  const apiKey = (text.match(/apiKey["']?\s*:\s*["'](AIza[0-9A-Za-z_-]{30,})["']/) || [])[1];
  const dbUrl = (text.match(/["'](https:\/\/[a-z0-9-]+(?:-default-rtdb)?\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app))["']/) || [])[1];
  const bucket = (text.match(/storageBucket["']?\s*:\s*["']([a-z0-9.-]+\.(?:appspot\.com|firebasestorage\.app))["']/) || [])[1];
  const projectId = (text.match(/projectId["']?\s*:\s*["']([a-z0-9-]+)["']/) || [])[1];
  if (!apiKey && !dbUrl && !bucket && !projectId) return;
  info.firebase = true;
  if (apiKey) add('firebase_config', 'secrets', 'info', 'The Firebase web config is in the browser code, as intended.', 'Firebase web keys are public by design; the protection is in the Security Rules. Restrict the key to your domains in Google Cloud.');
  if (dbUrl || bucket) add('fb_rules', 'data', 'medium', 'This app uses Firebase: make sure its database and storage are not readable by anyone.', `In your own Firebase console, open the Rules of Realtime Database or Firestore, and of Storage. Reads and writes should require sign-in and reach only the signed-in user's own data; the Rules Playground there tests each rule. ${SB_NEVER_READS}`);
}

// ------------------------------------------------------------------ 6. scoring and the report

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COST = { critical: 45, high: 25, medium: 10, low: 4, info: 0 };
const WEIGHT = { security: 2, data: 2, secrets: 2, email: 1, performance: 1, accessibility: 1, seo: 1, reliability: 1 };
export const gradeOf = (score) => (score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F');

export function score(findings, checked) {
  const cats = {};
  for (const [key] of CATEGORIES) {
    if (!checked[key]?.ran) { cats[key] = { score: null, note: checked[key]?.note || 'not checked' }; continue; }
    const mine = findings.filter((f) => f.cat === key);
    const s = Math.max(0, 100 - mine.reduce((t, f) => t + SEV_COST[f.sev], 0));
    cats[key] = { score: s, note: checked[key].note || '' };
  }
  const ran = Object.entries(cats).filter(([, v]) => v.score != null);
  const wsum = ran.reduce((t, [k]) => t + WEIGHT[k], 0) || 1;
  let overall = Math.round(ran.reduce((t, [k, v]) => t + v.score * WEIGHT[k], 0) / wsum);
  // Something exposed now caps the grade, however good the rest is.
  if (findings.some((f) => f.sev === 'critical')) overall = Math.min(overall, 49);
  else if (findings.some((f) => f.sev === 'high')) overall = Math.min(overall, 69);
  return { categories: cats, overall, grade: gradeOf(overall) };
}

// The whole check. deps (for tests): { fetchImpl, dns, tls, env, now }.
export async function runCheck(rawUrl, { owner = false, maps = true, deps = {} } = {}) {
  const target = normalizeTarget(rawUrl);
  if (!target) return { error: 'bad_url', message: 'That is not a public web address. Pass a domain such as myapp.com or a full https:// address.' };
  const net = makeNet({ fetchImpl: deps.fetchImpl });
  const dns = deps.dns || new Resolver({ timeout: 5000, tries: 2 });
  const env = deps.env || process.env;
  const ctx = { host: target.hostname, origin: target.origin, tls: deps.tls || tlsInfo };
  const started = Date.now();

  const findings = [];
  const add = (id, cat, sev, title, fix) => findings.push({ id, cat, sev, title, fix });
  const metrics = {};
  const info = {};
  const checked = {};

  const home = await net.get(target.href, { max: 2_000_000, headers: { Accept: 'text/html,application/xhtml+xml' } });
  if (home.status === 0 && home.error === 'tls') {
    // Maybe the app only answers on plain HTTP.
    const plain = await net.get(`http://${ctx.host}/`, { max: 1000 });
    if (plain.status) return finish({ fatal: 'no_https' });
  }
  if (!home.status) return { error: 'unreachable', host: ctx.host, message: `${ctx.host} did not answer (${home.error || 'no response'}). Check that the app is deployed at a public address and spelled right.` };
  const finalUrl = home.url;
  if (!finalUrl.startsWith('https://')) add('no_https', 'security', 'critical', 'The app ends up on plain HTTP.', 'Serve the app over HTTPS only and redirect every http:// request to https://.');
  if (home.status >= 500) add('http_error', 'reliability', 'critical', `The home page answers with an error (HTTP ${home.status}).`, 'Check the server logs and the latest deploy.');
  else if (home.status >= 400) add('http_error', 'reliability', 'high', `The home page answers HTTP ${home.status}.`, 'Make sure the public home page answers 200 for a visitor who is not signed in.');

  const page = readHtml(home.text, finalUrl);
  const origin = new URL(finalUrl).origin;
  const stack = stackOf(home.headers, home.text);
  const firstParty = page.scripts.map((s) => s.src).filter((u) => u && new URL(u).hostname === new URL(finalUrl).hostname);

  // Public checks, in parallel (each one is polite on its own).
  const shared = SHARED_APP_HOST.test(ctx.host);
  const mailDomain = shared ? '' : mailDomainOf(ctx.host);
  const plainHttp = net.get(`http://${ctx.host}/`, { follow: false, max: 0 });
  const tasks = [
    (async () => {
      headerFindings(home.headers, add);
      if (page.mixed && finalUrl.startsWith('https://')) add('mixed_content', 'security', 'medium', `${plural(page.mixed, 'file')} load over plain HTTP on an HTTPS page.`, 'Load every script, style, frame and image over https://; browsers block or flag the rest.');
      const r = await plainHttp;
      const loc = r.headers.get('location') || '';
      metrics.http_redirects_to_https = r.status >= 300 && r.status < 400 && /^https:\/\//i.test(new URL(loc, `http://${ctx.host}/`).href);
      if (r.status >= 200 && r.status < 300) add('http_no_redirect', 'security', 'high', 'Plain http:// still serves the app instead of redirecting to https://.', 'Redirect every http:// request to https:// (most hosts have a "force HTTPS" switch).');
      checked.security = { ran: true };
    })(),
    (async () => {
      metrics.source_map_public = await sourceMapCheck(net, firstParty, add);
      checked.secrets = { ran: true, note: owner ? '' : 'public part only: the scan of the browser code for keys runs on an app you own' };
    })(),
    performanceChecks(net, home, page, firstParty, add, metrics).then(() => { checked.performance = { ran: true }; }),
    (async () => {
      accessibilityChecks(page, add, metrics);
      checked.accessibility = { ran: true, note: page.shell ? 'the page renders in the browser, so only its HTML shell was read; colour contrast is not checked from outside' : 'colour contrast and keyboard use are not checked from outside' };
    })(),
    seoChecks(net, origin, home, page, add, metrics).then(() => { checked.seo = { ran: true, note: page.shell ? 'the page renders in the browser; search engines that do not run scripts see the shell' : '' }; }),
    reliabilityChecks(net, { ...ctx, origin }, home, add, metrics).then(() => { checked.reliability = { ran: true }; }),
    (async () => {
      if (!mailDomain) { checked.email = { ran: false, note: 'skipped: shared platform address; check your own domain once it is connected' }; return; }
      const m = await emailCheck(mailDomain, dns);
      info.email = m;
      emailFindings(m, add);
      checked.email = { ran: true, note: mailDomain };
    })(),
    (async () => {
      const urls = await mcpFind(net, origin, home.text);
      if (!urls.length) return;
      info.mcp = maps ? await mapsLookup(net, urls) : urls.map((url) => ({ url, key: mapsKey(url), on_7maps: null, page: null }));
    })(),
  ];
  const psiKey = env.PAGESPEED_API_KEY || '';
  if (psiKey) tasks.push(pageSpeed(net, finalUrl, psiKey, add, metrics));
  await Promise.all(tasks);

  // Deep checks: only when the person said the app is theirs AND the app carries the token.
  let ownership = 'not_requested';
  if (owner) {
    const where = await ownershipToken(net, origin, home.text);
    if (!where) {
      ownership = 'token_missing';
    } else {
      ownership = 'verified_' + where;
      await exposedFiles(net, origin, home.text, add);
      const files = await clientText(net, home, page);
      secretScan(files, add);
      const all = files.map((f) => f.text).join('\n');
      supabaseCheck(ctx.host, all, add, info);
      firebaseCheck(all, add, info);
      if (info.supabase && !stack.includes('supabase')) stack.push('supabase');
      if (info.firebase && !stack.includes('firebase')) stack.push('firebase');
      checked.data = { ran: true, note: [info.supabase ? 'Supabase found: Security Advisor steps below; this check never reads your data' : '', info.firebase ? 'Firebase found: check its Security Rules' : ''].filter(Boolean).join('; ') || 'exposed files checked; no Supabase or Firebase found' };
      checked.secrets = { ran: true };
    }
  }
  if (!checked.data) checked.data = { ran: false, note: ownership === 'token_missing' ? 'not checked: the ownership token was not found on the app' : 'not checked: runs only on an app you own' };
  return finish({});

  function finish({ fatal }) {
    if (fatal === 'no_https') {
      add('no_https', 'security', 'critical', 'The app does not answer over HTTPS.', 'Serve the app over HTTPS (most hosts issue a certificate automatically once the domain is connected) and redirect http:// to https://.');
      checked.security = { ran: true };
    }
    findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || CATEGORIES.findIndex(([k]) => k === a.cat) - CATEGORIES.findIndex(([k]) => k === b.cat));
    const s = score(findings, checked);
    return {
      version: VERSION,
      host: ctx.host,
      url: target.href,
      checked_at: new Date(deps.now || Date.now()).toISOString(),
      seconds: Math.round((Date.now() - started) / 100) / 10,
      grade: s.grade,
      score: s.overall,
      categories: s.categories,
      findings,
      metrics,
      stack,
      ownership,
      token: localToken(ctx.host),
      email_domain: mailDomain || null,
      supabase: info.supabase || null,
      mcp: info.mcp || [],
      requests: Object.fromEntries(net.hosts),
    };
  }
}

// ------------------------------------------------------------------ 7. the text report and the link

const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED ', low: 'LOW ', info: 'INFO' };
const CAT_LABEL = Object.fromEntries(CATEGORIES);

// The report link: results packed into the address fragment (#r=...), which browsers never
// send to a server. deflate-raw + base64url; kept under LINK_MAX characters by trimming.
export function reportLink(report) {
  const short = { critical: 'c', high: 'h', medium: 'm', low: 'l', info: 'i' };
  const p = {
    v: 1,
    h: report.host,
    t: report.checked_at.slice(0, 16).replace('T', ' ') + ' UTC',
    g: report.grade,
    s: report.score,
    o: report.ownership.startsWith('verified') ? 1 : 0,
    c: Object.fromEntries(Object.entries(report.categories).map(([k, v]) => [k, [v.score, v.note]])),
    f: report.findings.map((f) => [f.id, f.cat, short[f.sev], f.title, f.fix]),
    m: report.metrics,
    st: report.stack,
    e: report.email_domain,
    mc: (report.mcp || []).map((s) => [s.url, s.on_7maps === true ? 1 : s.on_7maps === false ? 0 : -1]),
  };
  const pack = () => deflateRawSync(Buffer.from(JSON.stringify(p)), { level: 9 }).toString('base64url');
  let enc = pack();
  // Too long: drop the fix sentences (the page has its own), then the info and low items.
  if (enc.length > LINK_MAX) { p.f = p.f.map((x) => (x[2] === 'c' || x[2] === 'h' ? x : x.slice(0, 4))); enc = pack(); }
  for (const drop of ['i', 'l', 'm']) {
    if (enc.length <= LINK_MAX) break;
    const before = p.f.length;
    p.f = p.f.filter((x) => x[2] !== drop);
    p.x = (p.x || 0) + before - p.f.length;
    enc = pack();
  }
  if (enc.length > LINK_MAX) { p.f = p.f.slice(0, 10).map((x) => [x[0], x[1], x[2], String(x[3]).slice(0, 120)]); p.m = {}; enc = pack(); }
  return `${REPORT_BASE}#r=${enc}`;
}

export function textReport(report, { link = true } = {}) {
  const lines = [];
  const now = report.findings.filter((f) => f.sev === 'critical' || f.sev === 'high');
  const later = report.findings.filter((f) => f.sev === 'medium' || f.sev === 'low');
  lines.push(`7IT Guard ${report.version} · ${report.host} · ${report.checked_at.slice(0, 10)} · run on this machine, nothing about the app sent to 7IT`);
  lines.push(`Grade ${report.grade} (${report.score}/100) · ${now.length} to fix before shipping · ${later.length} to fix soon`);
  lines.push('');
  for (const [key, label] of CATEGORIES) {
    const c = report.categories[key];
    if (c.score == null) { lines.push(`  ${label.padEnd(14)}   -  ${c.note}`); continue; }
    const bar = '█'.repeat(Math.round(c.score / 10)) + '░'.repeat(10 - Math.round(c.score / 10));
    const n = report.findings.filter((f) => f.cat === key && f.sev !== 'info').length;
    lines.push(`  ${label.padEnd(14)} ${String(c.score).padStart(3)}  ${bar}  ${n ? plural(n, 'issue') : 'clear'}${c.note ? ` (${c.note})` : ''}`);
  }
  let i = 0;
  const item = (f) => `  ${String(++i).padStart(2)}. ${SEV_LABEL[f.sev]} ${CAT_LABEL[f.cat]}: ${f.title} ${f.fix}`;
  if (now.length) lines.push('', 'Fix before shipping', ...now.map(item));
  if (later.length) {
    lines.push('', 'Fix soon', ...later.slice(0, 10).map(item));
    if (later.length > 10) lines.push(`      and ${later.length - 10} more in the full report`);
  }
  if (!now.length && !later.length) lines.push('', 'Nothing to fix was found in these checks.');
  if (report.ownership !== 'not_requested' && report.ownership !== 'token_missing') {
    lines.push('', `Deep checks ran (ownership token found as a ${report.ownership.replace('verified_', '')}).`);
    const g = report.supabase?.guide;
    if (g) {
      lines.push('', `Supabase: ${g.never_reads} It read only the code your app already sends to every visitor; no request went to your Supabase project.`);
      if (g.secret_steps) {
        lines.push('A Supabase secret is in that code. Fix it first:');
        g.secret_steps.forEach((s, n) => lines.push(`  ${n + 1}. ${s}`));
        lines.push('  Secret key prompt for your AI builder:', `  "${g.secret_prompt}"`);
      }
      lines.push(`${g.title}. ${g.means}`);
      g.steps.forEach((s, n) => lines.push(`  ${n + 1}. ${s}`));
      lines.push('  Prompt for your AI builder:', `  "${g.ai_prompt}"`);
    }
  } else {
    lines.push('', report.ownership === 'token_missing'
      ? 'Deep checks did not run: the ownership token is not on the app yet.'
      : 'Exposed files, keys in the browser code and the database behind the app are checked only on an app you own.');
    lines.push(`  To include them, add this inert token to the app, deploy, and run again with --owner:`);
    lines.push(`  <meta name="7it-site-verification" content="${report.token}"> in the home page <head>,`);
    lines.push(`  or a file at https://${report.host}/7it-verify.txt containing ${report.token}`);
  }
  const mcp = report.mcp || [];
  if (mcp.length) {
    lines.push('', `MCP server${mcp.length === 1 ? '' : 's'} published by this app (for AI agents):`);
    for (const s of mcp) {
      if (s.on_7maps === true) lines.push(`  ${s.url}: on 7Maps, the public map of MCP servers: ${s.page}`);
      else if (s.on_7maps === false) lines.push(`  ${s.url}: not on 7Maps yet. Its owner can add it: ${MAPS_SUBMIT}`);
      else lines.push(`  ${s.url}: not looked up on 7Maps in this run.`);
    }
    if (mcp.some((s) => s.on_7maps === true)) lines.push(`  If the server is yours, verify ownership on 7Maps so agents see it is yours: ${MAPS_CLAIM}`);
  }
  const hosts = Object.keys(report.requests);
  lines.push('', `Requests: ${Object.values(report.requests).reduce((a, b) => a + b, 0)} from this machine to ${hosts.slice(0, 4).join(', ')}${hosts.length > 4 ? ` and ${hosts.length - 4} more` : ''}, plus public DNS. ${report.seconds} s.`);
  if (link) lines.push(`Full report: ${reportLink(report)}`);
  lines.push(`Not checked from outside: load and traffic spikes, scale limits, architecture, business logic behind the login, cost at scale, backups and recovery, compliance. A senior review covers these: ${REVIEW_URL}`);
  return lines.join('\n');
}

// ------------------------------------------------------------------ 8. the command line

const HELP = `7IT Guard ${VERSION}: check a deployed web app from the outside, on this machine.

  node check.mjs <address> [--owner] [--json] [--no-link] [--no-7maps]
  node check.mjs <address> --token

  --owner     the person running this owns the app: also check exposed files and keys in the
              browser code, and name the Supabase or Firebase backend that code uses, with the
              steps to check its rules in your own account (needs the ownership token on the
              app; --token prints it). This check never reads your data.
  --json      machine-readable output
  --no-link   leave out the full report link
  --no-7maps  when the app publishes an MCP server, do not download the 7Maps list that
              says whether the server is on the map

Optional: PAGESPEED_API_KEY=<your own Google API key> adds Google PageSpeed scores.`;

export async function main(argv) {
  const args = argv.filter((a) => !a.startsWith('--'));
  const flags = new Set(argv.filter((a) => a.startsWith('--')));
  if (flags.has('--help') || !args[0]) { console.log(HELP); return args[0] ? 0 : 2; }
  if (flags.has('--token')) {
    const t = normalizeTarget(args[0]);
    if (!t) { console.log('That is not a public web address.'); return 2; }
    const token = localToken(t.hostname);
    console.log(`Ownership token for ${t.hostname}: ${token}\n\nAdd ONE of these to the app and deploy:\n  <meta name="7it-site-verification" content="${token}">   (inside <head> of the home page)\n  https://${t.hostname}/7it-verify.txt containing exactly: ${token}\n\nThe token runs nothing and can be removed after the check.`);
    return 0;
  }
  const report = await runCheck(args[0], { owner: flags.has('--owner'), maps: !flags.has('--no-7maps') });
  if (report.error) {
    console.log(flags.has('--json') ? JSON.stringify(report) : report.message);
    return report.error === 'bad_url' ? 2 : 3;
  }
  if (flags.has('--json')) {
    console.log(JSON.stringify({ ...report, report_url: flags.has('--no-link') ? null : reportLink(report), review_url: REVIEW_URL }, null, 1));
  } else {
    console.log(textReport(report, { link: !flags.has('--no-link') }));
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.log(`7IT Guard stopped: ${e?.message || e}`); process.exitCode = 1; });
}
