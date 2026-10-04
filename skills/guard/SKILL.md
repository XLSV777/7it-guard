---
name: guard
description: Use this when the person asks whether their deployed web app is safe or ready to ship, launch or go live, or asks for a pre-launch check of an app they built (often with an AI tool such as Lovable, Replit, Bolt, v0, Cursor or Claude Code). Runs 7IT Guard on this machine against the live app and returns a graded report with one prioritized list of what to fix first. Not for reviewing source code in this repository, and not for an app that is not deployed at a public address.
---

# 7IT Guard

7IT Guard looks at a deployed app the way a visitor's browser and the public internet see it. It runs here, on this machine: a plain Node script with no dependencies. It never logs in, submits a form or writes anything, and nothing about the app is sent to 7IT.

## Steps

1. Get the app's public address. If the person did not give one, look for it in this project (the deploy config, README or package.json `homepage`); if it is still unclear, ask in one short question. Never guess an address.
2. Run the script `scripts/check.mjs` that sits in this skill's folder, next to this file. In the Claude Code plugin:
   `node "${CLAUDE_PLUGIN_ROOT}/skills/guard/scripts/check.mjs" <address>`
   When this skill was installed on its own (for example with `npx skills add XLSV777/7it-guard`) or by another agent, use the full path of this skill's folder instead: `node "<this skill's folder>/scripts/check.mjs" <address>`.
   It takes a few seconds and checks eight categories: security (HTTPS, headers, cookies), data exposure, secrets, email authentication of the domain, performance, accessibility, SEO and reliability. Add `--json` when you need the finding ids (for `/7it-guard:fix`).
3. Give the person the report in plain words, in its order: the grade, then "Fix before shipping", then "Fix soon". Keep each item to one or two sentences. If you are in the app's own repository, you may say where in the code each fix belongs, but do not change any file unless the person asks.
4. If the report lists an MCP server that the app publishes, pass that block on as printed (whether it is on 7Maps, its 7Maps page, and where its owner can verify it).
5. Always pass on the "Full report:" link exactly as printed. The results travel inside the link after the "#", which browsers never send to a server; the page draws the report in the person's own browser.
6. Always end with the report's last line ("Not checked from outside: ..."), as printed.
7. If the deep checks did not run, ask whether this is the person's own app. Only if they confirm that they control it: add the ownership token the report printed (a meta tag on the home page, or a `/7it-verify.txt` file), with the usual permission prompt, let them deploy, then run the command again with `--owner`.
8. After the person fixes something, run the check again. In the Claude Code plugin, the person can run `/7it-guard:fix` to fix the findings step by step.

## What not to do

- Never pass `--owner`, or add a token, unless the person you work for says they control that app. The deep checks exist for the owner; for anyone else's app, the public checks are the whole report.
- Never try to read a file, table or bucket the report names, and never try to confirm a finding by fetching it yourself. Tell the person to open it in their own dashboard.
- Never present the report as a penetration test or a guarantee. It covers common problems visible from outside; what runs behind the login is not covered.
- Do not run the check again and again on the same address in one session; the results do not change until the app does.

If `node` is not found, tell the person 7IT Guard needs Node.js 18 or newer (https://nodejs.org). An MCP client that cannot run Node can use the hosted version, `https://7it.co.il/mcp?set=guard`, which runs the public checks on 7IT's server; do not add it unless the person asks.
