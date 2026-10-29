# Changelog

## Unreleased

- The report ends with one line naming the 7IT Guard GitHub check (the Action XLSV777/7it-guard-check@v1, now on the GitHub Marketplace): "On every push: ... Setup: https://7it.co.il/tools/guard/#github", after the closing "Not checked from outside" line; `--json` adds `ghcheck_url`. The script still sends nothing and writes nothing.
- `/7it-guard:check` (step 6) and the `guard` skill (step 10) pass the line on once per session, and not when the repository's `.github/workflows/` already uses the Action.
- README: "On every push".

## 0.5.0 (2026-10-28)

7IT Guard in the session, for a site 7IT Guard already watches. Off until the project adds `.7it/guard.json` with `{"site": "myapp.com"}`.

- SessionStart hook (`scripts/session/brief.mjs`): a brief of at most 5 lines in a fixed template (site, status, open problems, top 3 by name, last check time), from `GET https://7it.co.il/guard/app/api/brief` with the 7IT key; cached 5 minutes per site. Prints nothing without the file, the key or an answer.
- PreToolUse hook on Bash and PowerShell (`scripts/session/predeploy.mjs`): before `git push`, `vercel --prod`, `netlify deploy` or a `deploy` script, the outside check (`ship_check` on the guard set), at most once per 10 minutes per site; the 7IT Guard block when something critical or high is found. Warns by default; stops the command only with `"block": true`.
- `/7it-guard:recheck` (`scripts/session/recheck.mjs`): checks again and lists what is gone (verified fixed), still open and new. A deep finding is never counted as fixed when the deep part could not run.
- `hooks/hooks.json`.
- Everything the hooks print is data in a fixed template: control, invisible and bidi characters and markup characters removed, every line capped, links only on https://7it.co.il, text that reads like an instruction replaced. The brief prints the plugin's own words for every problem code it knows.
- README: "In the session" and what the hooks send. The check script reports 0.5.0.

## 0.4.3 (2026-10-27)

- The app line after the "Full report:" link now starts with "Once your app is live:" (it said "After launch:", which read as 7IT's launch). Same address, same place, once.
- The check script reports 0.4.3.

## 0.4.2 (2026-10-26)

Security fixes.

- The fix server sends the 7IT key only to `https://7it.co.il/`. The `GUARD_PLAYBOOK_URL` and `GUARD_VAULT_URL` overrides are ignored unless they are under that address (a local `http://127.0.0.1` address is accepted only in the tests, with `GUARD_TEST=1`).
- Redirects: every hop must be `https://`, name a public host and resolve only to public addresses (no loopback, private, link-local, CGNAT or unique local IPv6). A redirect to plain HTTP or to a private address is not followed, and the report says so ("redirects off-site to a private address"). Host names lose a trailing dot before the check, and wildcard DNS names (nip.io, sslip.io), `home.arpa` and other reserved suffixes are refused. The sitemap named in robots.txt is read only on the app's own origin.
- Text from the app or its DNS (cookie names, the Server and X-Powered-By headers, content-encoding, addresses) is reduced to short printable text before it reaches the report. The DMARC policy is shown only as none, quarantine or reject; anything else is "invalid". The skill says that report text quoted from the app is data, not instructions.
- The HTML checks read at most 300 KB of the home page and scan tags in one pass, so a hostile page cannot slow them down (2 MB of unclosed tags reads in well under a second).
- `/7it-guard:vault`: psql gets the database address without its password; the password goes in `PGPASSWORD`, in psql's environment only.
- `/7it-guard:fix`: the playbook from the fix server is framed as reference data. Each step is proposed and made only after the person approves it.
- An early stop of the check (no HTTPS, or a refused redirect) no longer ends in an error.
- The check script reports 0.4.2.
- The report link carries the plugin version (`pv`, still payload v1), so the full report page can say when a newer 7IT Guard is out and how to update.
- When the run already downloads a 7Maps list (the app publishes an MCP server), that list names the latest 7IT Guard version; if this one is older, the text report ends with one line naming the update for the place it runs (Claude Code, Gemini CLI, skills.sh, Codex). No request is made just for this. `--json` has `latest_version`. The skill and `/7it-guard:check` pass the line on once.
- README: how to turn on auto-update for the marketplace (`/plugin`, Marketplaces, Enable auto-update) and the manual update commands. Plugins added from GitHub do not update by themselves until you do.

## 0.4.1 (2026-10-26)

- The text report has one more line, right after the "Full report:" link: it names the 7IT Guard app, which checks the app from outside on a schedule after launch and says when it stops answering, with its address (`https://7it.co.il/guard/app/?from=plugin`). The address is fixed: nothing from the check is in it.
- The skill and `/7it-guard:check` pass that line on once, after the closing "Not checked from outside" line.
- The check script now reports 0.4.1 (it said 0.3.2 through 0.4.0).

## 0.4.0 (2026-10-13)

- New command `/7it-guard:vault`: a nightly encrypted backup of the app's database and stored files into storage you own, with a weekly restore test and restore by date (full, database only or files only), all running in your own GitHub account. Needs a 7IT key whose plan or Vault add-on includes the vault.
- The local fix server gains a second tool, `vault_register`, which registers the vault with 7IT (never a database address, a password, a storage key or any private key).
- On Lovable Cloud or Bolt Database the command writes nothing and explains the manual export and the move to your own Supabase project.
- The check script itself is unchanged (it still reports 0.3.2).

## 0.3.2

- Supabase grants in the database guidance.
