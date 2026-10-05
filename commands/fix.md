---
description: Fix what the last 7IT Guard check found, with your approval for every change, then check again.
argument-hint: <app address, if no check ran in this session>
disable-model-invocation: true
---

The person wants to fix what 7IT Guard found. Address, if given: $ARGUMENTS

1. Use the 7IT Guard report from this session. If there is none, run `node "${CLAUDE_PLUGIN_ROOT}/skills/guard/scripts/check.mjs" <address> --json` first (add `--owner` only if the person already confirmed the app is theirs and the token is on it). Keep the `id` of each finding and the `stack` list.
2. Call the `get_fix_playbook` tool once, with the finding ids and the stack. It makes a request only when the person has set a 7IT key, and then sends only the key, the ids and the platform names.
   - With a key, it returns the strict playbook: follow it.
   - Without a key, it says so and makes no request: fix from the report itself (each item carries its fix; the "Full report" page has copyable snippets).
3. Work in this repository, most severe first. Before each change, say in one sentence what will change and why, and wait for the person's approval. Never change secrets yourself: when a key was exposed, tell the person to rotate it in that service's dashboard. Never touch production data or dashboards, and never query the app's database. For Supabase, give the person the Security Advisor steps and the AI builder prompt from the report, and let them run it in their own account.
4. Things that are not in the code (DNS records, host settings, database policies): give the exact record or setting and where it goes.
5. When the person has deployed, run the check again with the same flags and show what changed.

Never present the result as a penetration test or a guarantee. What runs behind the login, load and scale are not covered by any outside check; a senior review covers them: https://7it.co.il/services/ai-built-apps/
