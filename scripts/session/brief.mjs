#!/usr/bin/env node
// SessionStart hook (hooks/hooks.json): at most 5 lines about the project's watched site, in a fixed template.
// Prints nothing and sends nothing without .7it/guard.json (with a site) in the project, without the 7IT key, or when
// 7IT does not answer. One request: GET https://7it.co.il/guard/app/api/brief?site=<site> with the key; the answer is
// cached 5 minutes per site so resume and compact do not ask again. Always exits 0: a brief never stops a session.
import { BRIEF_CACHE_MS, briefLines, fetchBrief, keyOf, projectDir, readConfig, readState, readStdin, writeState } from './lib.mjs';

async function main() {
  const input = await readStdin();
  const cfg = readConfig(projectDir(input));
  if (!cfg || !cfg.brief) return;
  const key = keyOf();
  if (!key) return;
  const now = Date.now();
  const c = readState(cfg.site, 'brief');
  let b = c && typeof c.at === 'number' && now - c.at < BRIEF_CACHE_MS ? c.b : null;
  if (!b) {
    b = await fetchBrief(cfg.site, key).catch(() => null);
    if (!b) return;
    writeState(cfg.site, 'brief', { at: now, b });
  }
  const text = briefLines(cfg.site, b).join('\n');
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: text }, systemMessage: text }));
}
main().catch(() => {}).finally(() => process.exit(0));
