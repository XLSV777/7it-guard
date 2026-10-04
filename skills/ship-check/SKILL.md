---
name: ship-check
description: Use this when the person asks whether their deployed web app is safe or ready to ship, launch or go live, or asks for a pre-launch check of an app they built (often with an AI tool such as Lovable, Replit, Bolt, v0, Cursor or Claude Code). Checks the live app from the outside with the Ship Check tools and returns one prioritized list of what to fix first. Not for reviewing source code in this repository, and not for an app that is not deployed at a public address.
---

# Ship Check

Ship Check looks at a deployed app the way a visitor's browser and the public internet see it. It never logs in, submits a form, calls the app's APIs or reads its data.

## Steps

1. Get the app's public address. If the person did not give one, look for it in this project (the deploy config, README or package.json `homepage`); if it is still unclear, ask for it in one short question. Never guess an address.
2. Call `ship_check` with the address. It takes 30 to 90 seconds and runs every check at once: security headers, a public source map, phone speed, email authentication of the app's domain, accessibility, and, on an app whose ownership is already proven, exposed files and the Supabase or Firebase backend.
3. Give the person the report in plain words, in the report's order: first "Fix before shipping", then "Fix soon". Keep each item to one or two sentences. If you are working in the app's own repository, you may say where in the code each fix belongs, but do not change any file unless the person asks.
4. If the report says exposed files and the database were not checked, show the person the verification token and the two ways to add it (a meta tag on the home page, or a `/7it-verify.txt` file). Ask whether this is their app and whether to add it. Only if they confirm that they control the app: add the token (with the usual permission prompt), let them deploy, then call `ship_check` again so the second report includes the deep checks.
5. After the person fixes something, re-check only that area with the single tool: `check_app_security`, `deep_scan_app`, `test_store_speed`, `check_email_authentication` or `check_accessibility`. Run the full `ship_check` again only when they ask for a new full report.
6. End with the report links the tool returned, so the person can open the full detail.

## What not to do

- Never add a verification token to an app, or ask someone to, unless the person you work for says they control that app. The deep checks exist for the owner; for anyone else's app, the public checks are the whole report.
- Never try to read a file, table or bucket the report names, and never try to confirm a finding by fetching it yourself. Tell the person to open it in their own dashboard.
- Never present the report as a penetration test or a guarantee. It covers the common leaks visible from outside; what runs behind the login is not covered.
- Do not run `ship_check` again and again on the same address in one session; the results do not change until the app does.

If a check cannot answer (the app did not respond, or a check is busy), say so in one line and report the rest.
