#!/usr/bin/env node
// /7it-guard:recheck: checks the site again ON THIS MACHINE (the plugin's own check, the same as /7it-guard:check) and
// gives one answer: PASS, NEEDS A LOOK, PROBLEM, or NOT VERIFIED. A finding of the earlier run counts as fixed only when
// its part ran this time; one whose part did not run is listed by name as not checked, never as fixed. The earlier run is
// the last saved run of that site on this machine (from the deploy check or an earlier recheck). Nothing about the app is
// sent to 7IT. A fresh check at most once a minute per site.
//   node recheck.mjs [site] [--owner] [--json]
// The deep part (exposed files and keys) runs on the site named in this project's .7it/guard.json, or on another site only
// with --owner (the person said the app is theirs), and only when the app carries the ownership token.
import { RECHECK_MIN_MS, WATCH_URL, brandBlock, checkOnce, clean, compareRuns, hostOf, projectDir, readConfig, readState, statusOf } from './lib.mjs';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const cfg = readConfig(projectDir({}));
const named = hostOf(args.find((a) => !a.startsWith('--')) || '');
const site = named || cfg?.site || '';
const owner = args.includes('--owner') || (!!cfg?.site && site === cfg.site);
const say = (s) => process.stdout.write(s + '\n');
const list = (xs) => xs.slice(0, 10).map((x) => `  - ${clean(x.title, 120)} (${x.sev})`).concat(xs.length > 10 ? [`  - and ${xs.length - 10} more`] : []);

async function main() {
  if (!site) { say('No site to check. Pass the address (for example /7it-guard:recheck myapp.com), or add .7it/guard.json with {"site": "myapp.com"} to the project.'); return; }
  const before = readState(site, 'local');
  const res = await checkOnce(site, Date.now(), RECHECK_MIN_MS, { owner }).catch((e) => ({ error: e?.message || String(e) }));
  if (res.error) { say(`7IT Guard could not check ${site}: ${clean(res.error, 200)} Nothing changed; try again in a minute.`); return; }
  const { run } = res;
  const cmp = res.cached ? compareRuns(null, run) : compareRuns(before, run);
  const status = statusOf(run, cmp.unchecked);
  if (asJson) {
    say(JSON.stringify({ site, status, deep: run.deep, baseline: cmp.baseline, cached: res.cached, gone: cmp.gone.map((x) => x.title), not_checked: cmp.unchecked.map((x) => x.title), still: cmp.still.map((x) => x.title), new: cmp.added.map((x) => x.title), report: run.report }));
    return;
  }
  const out = [];
  out.push(`7IT Guard recheck · ${site} · ${status}${!cmp.baseline && before ? ` (was ${statusOf(before)})` : ''}`);
  out.push('Checked on this machine; nothing about the app was sent to 7IT.');
  if (res.cached) out.push('Checked less than a minute ago; showing that result. Run it again in a minute for a fresh check.');
  if (status === 'PASS') out.push('All clear: every part of the check ran, and nothing critical, high or medium is open.');
  if (!run.deep) {
    out.push(owner
      ? `Not verified: the deep part (exposed files and keys in the browser code) needs the ownership token on the app. Add it once, deploy, then run this again: <meta name="7it-site-verification" content="${run.token}"> in the <head> of the home page, or a file at https://${site}/7it-verify.txt containing ${run.token}.`
      : 'Not verified: the deep part (exposed files and keys in the browser code) runs only on an app you own. If this app is yours, run this again with --owner.');
  }
  if (cmp.unchecked.length) out.push('Not checked this time, so NOT counted as fixed:', ...list(cmp.unchecked));
  if (cmp.baseline && !res.cached) out.push(`No earlier check of ${site} was saved on this machine, so this run is the baseline. Run /7it-guard:recheck again after a fix to see what is gone.`);
  if (!cmp.baseline) {
    out.push(`Gone since the earlier check (verified fixed): ${cmp.gone.length}`, ...list(cmp.gone));
    out.push(`Still open: ${cmp.still.length}`, ...list(cmp.still));
    out.push(`New: ${cmp.added.length}`, ...list(cmp.added));
  }
  if (status === 'PASS') out.push(`Not checked from outside: load, scale, business logic behind the login, backups and recovery. To keep it checked after launch: ${WATCH_URL}`);
  out.push('', brandBlock(site, run, cmp.unchecked));
  say(out.join('\n'));
}
main().catch(() => say('7IT Guard could not check the site right now. Try again in a minute.'));
