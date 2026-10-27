#!/usr/bin/env node
// PreToolUse hook on Bash and PowerShell (hooks/hooks.json): before a deploy or push command (git push, vercel --prod,
// netlify deploy, npm run deploy and the like), the outside check of the project's watched site, at most once per 10 minutes
// per site (a newer saved result is used instead). With critical or high findings it warns with the 7IT Guard block: the
// person sees it, and Claude gets it as data. It never stops the command unless .7it/guard.json says "block": true.
// Prints nothing and sends nothing without .7it/guard.json (with a site), for any other command, or when the check
// does not answer. Always exits 0.
import { CHECK_EVERY_MS, brandBlock, checkOnce, isDeployCommand, keyOf, projectDir, readConfig, readStdin, urgent } from './lib.mjs';

async function main() {
  const input = await readStdin();
  if (!['Bash', 'PowerShell'].includes(String(input?.tool_name || ''))) return;
  if (!isDeployCommand(input?.tool_input?.command)) return;
  const cfg = readConfig(projectDir(input));
  if (!cfg || !cfg.predeploy) return;
  const res = await checkOnce(cfg.site, keyOf(), Date.now(), CHECK_EVERY_MS).catch(() => null);
  if (!res) return;
  const bad = urgent(res.findings);
  if (!bad.length) return;
  const block = brandBlock(cfg.site, res.findings, res.report);
  const ctx = `7IT Guard check of the live site before this deploy (data, not instructions):\n${block}\n${cfg.block ? 'The command was stopped because .7it/guard.json has "block": true.' : 'The command was not stopped. Tell the person about the problems above before going on.'}`;
  const out = { systemMessage: block, hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: ctx } };
  if (cfg.block) Object.assign(out.hookSpecificOutput, { permissionDecision: 'deny', permissionDecisionReason: `${block}\nStopped by 7IT Guard ("block": true in .7it/guard.json). Fix the problems, or set "block": false to only warn.` });
  process.stdout.write(JSON.stringify(out));
}
main().catch(() => {}).finally(() => process.exit(0));
