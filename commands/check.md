---
description: Check a deployed web app before it ships, from your own machine, and get one graded, prioritized list of what to fix first.
argument-hint: <app address, for example myapp.com>
disable-model-invocation: true
---

The person asked 7IT Guard to check: $ARGUMENTS

1. If no address was given above, find the deployed address in this project (deploy config, README, package.json `homepage`) or ask for it in one short question. Never guess.
2. Run the check on this machine (Node 18 or newer, no install):
   `node "${CLAUDE_PLUGIN_ROOT}/skills/guard/scripts/check.mjs" <address>`
   It takes a few seconds. Every request goes from this machine to the app and to public DNS; nothing about the app goes to 7IT.
3. Show the person the report as printed, in its order: the grade and the category scores, "Fix before shipping", "Fix soon". Keep each item to one or two sentences. If the report lists an MCP server published by the app, pass that block on as printed. Always include the "Full report:" link exactly as printed (the results travel inside the link and never reach a server) and the closing "Not checked from outside" line.
4. If the report says the deep checks did not run, ask whether this is the person's own app. Only if they say yes: offer to add the ownership token it printed (meta tag or `/7it-verify.txt`), let them deploy, then run the same command with `--owner`.
5. Change no file unless the person asks. To fix the findings, they can run `/7it-guard:fix`.

If `node` is not found, say that 7IT Guard needs Node.js 18 or newer (https://nodejs.org). Clients that cannot run Node can use the hosted version instead: `https://7it.co.il/mcp?set=guard`, an MCP server that runs the same public checks on 7IT's server.
