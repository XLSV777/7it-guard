#!/usr/bin/env node
// /7it-guard:recheck: runs the outside check of the site again and says which earlier findings are gone (verified fixed),
// which are still open and which are new. The site: the argument, else .7it/guard.json. The earlier result is the last saved
// check of that site (from the pre-deploy check or an earlier recheck). A fresh check at most once a minute per site.
//   node recheck.mjs [site] [--json]
import { RECHECK_MIN_MS, brandBlock, brandStatus, checkOnce, clean, hostOf, keyOf, projectDir, readConfig, readState } from './lib.mjs';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const site = hostOf(args.find((a) => !a.startsWith('--')) || '') || readConfig(projectDir({}))?.site || '';
const say = (s) => process.stdout.write(s + '\n');

async function main() {
  if (!site) { say('No site to check. Pass the address (for example /7it-guard:recheck myapp.com), or add .7it/guard.json with {"site": "myapp.com"} to the project.'); return; }
  const before = readState(site, 'check');
  const res = await checkOnce(site, keyOf(), Date.now(), RECHECK_MIN_MS).catch(() => null);
  if (!res) { say(`7IT Guard could not check ${site} right now. Nothing changed; try again in a minute.`); return; }
  const prev = res.cached ? null : before;
  const now = new Map(res.findings.map((x) => [x.k, x]));
  const was = new Map((prev?.findings || []).map((x) => [x.k, x]));
  // A deep finding (exposed files, keys) cannot count as fixed when this check could not run the deep part.
  const deepGap = !!prev?.deep && !res.deep;
  const isDeep = (x) => x.area === 'exposed files' || (x.area === 'database' && !/supabase/i.test(x.title));
  const unseen = deepGap ? [...was.values()].filter((x) => !now.has(x.k) && isDeep(x)) : [];
  const gone = [...was.values()].filter((x) => !now.has(x.k) && !unseen.includes(x));
  const still = res.findings.filter((x) => was.has(x.k));
  const added = prev ? res.findings.filter((x) => !was.has(x.k)) : [];
  if (asJson) { say(JSON.stringify({ site, status: brandStatus(res.findings), had_earlier: !!prev, not_checked: unseen.map((x) => x.title), gone: gone.map((x) => x.title), still: still.map((x) => x.title), new: added.map((x) => x.title), report: res.report })); return; }
  const list = (xs) => xs.slice(0, 10).map((x) => `  - ${clean(x.title, 120)} (${x.sev})`).concat(xs.length > 10 ? [`  - and ${xs.length - 10} more`] : []);
  const out = [];
  if (res.cached) out.push(`Checked less than a minute ago; showing that result. Run it again in a minute for a fresh check.`);
  if (!prev && !res.cached) out.push(`No earlier check of ${site} was saved on this machine, so this is the baseline. Run /7it-guard:recheck again after a fix to see what is gone.`);
  else if (prev) {
    if (unseen.length) out.push(`Not checked this time (the deep part needs the 7IT key watching this site): ${unseen.length} earlier finding${unseen.length === 1 ? '' : 's'}, not counted as fixed.`);
    out.push(`7IT Guard recheck · ${site} · ${brandStatus(res.findings)} (was ${brandStatus(prev.findings || [])})`);
    out.push(`Gone since the earlier check (verified fixed from outside): ${gone.length}`, ...list(gone));
    out.push(`Still open: ${still.length}`, ...list(still));
    out.push(`New: ${added.length}`, ...list(added));
  }
  out.push('', brandBlock(site, res.findings, res.report));
  say(out.join('\n'));
}
main().catch(() => say('7IT Guard could not check the site right now. Try again in a minute.'));
