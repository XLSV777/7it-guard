# 7IT Guard

**The control room for apps built with AI.**

Docs: https://7it.co.il/tools/guard/

A Claude Code plugin that checks a deployed web app from the outside before it ships, **on your own machine**, and returns one graded, prioritized list of what to fix first. Made for apps built with AI tools (Lovable, Replit, Bolt, v0, Cursor, Claude Code), and works for any app at a public address.

The check is one readable Node script, [`skills/guard/scripts/check.mjs`](skills/guard/scripts/check.mjs) (inside the skill's folder, so the skill also works on its own in other agents): Node 18 or newer, built-in modules only, no dependencies, nothing to install.

## What it checks

Eight categories, each scored out of 100, an overall grade (A to F; anything exposed right now caps it), and severity on every finding:

- **Security**: HTTPS and the http-to-https redirect, HSTS, Content Security Policy (and whether it still allows inline scripts), clickjacking protection, nosniff, referrer and permissions policy, cross-origin isolation, cookie flags, mixed content, version banners, security.txt.
- **Secrets**: a public JavaScript source map; on your own app, also keys shaped like OpenAI, Anthropic, Stripe, GitHub, AWS, SendGrid, Slack and other secret keys in the code sent to browsers, and Supabase secrets (the service role key, an `sb_secret_` key, a database password). Each is reported by its kind and file, never its text.
- **Data exposure** (your own app only): `.env` files, a `.git` folder, backups, admin tools, directory listings and an open session list of an MCP gateway (MetaMCP); and whether the app's own browser code uses Supabase or Firebase. **This check never reads your data**: no request goes to the app's database, no table names, no counts, no rows. For Supabase, the report gives the guided Security Advisor step instead: open the Security Advisor in your own Supabase account, copy one prompt into your AI builder (it turns on Row Level Security with owner-only rules and shows you the SQL before it runs), and run the Advisor again. For Firebase, it points you to the Security Rules in your own console.
- **Email**: SPF, DMARC and DKIM (common selectors) of the app's domain, from public DNS. Skipped on shared platform addresses such as `myapp.lovable.app`.
- **Performance**: time to first byte, HTML weight, compression, script count and weight, render-blocking scripts, caching of versioned files. Google PageSpeed scores too, if you set your own key (below).
- **Accessibility** (from the HTML): page language, image text alternatives, form labels, button and link names, zoom, main heading and landmark. Colour contrast and keyboard use cannot be checked from outside; the report says so.
- **SEO**: title, meta description, canonical, Open Graph, noindex left on, robots.txt, sitemap.
- **Reliability**: home page status, certificate validity and expiry, redirect chain, real 404s, www and the bare domain.

When the app publishes an MCP server (a server card at `/.well-known/mcp/server-card.json`, an AI catalog at `/.well-known/ai-catalog.json`, or an answer at `/mcp`), the report also names that server, says whether it is on [7Maps](https://7it.co.il/7maps/) (the public map of MCP servers, also by 7IT) with a link to its 7Maps page, and where its owner can verify it.

## Install

```
/plugin marketplace add XLSV777/7it-guard
/plugin install 7it-guard@7it-guard
```

Turn on updates: in `/plugin`, open Marketplaces, choose `7it-guard`, Enable auto-update. Plugins added from GitHub do not update by themselves until you do. To update by hand: `/plugin marketplace update 7it-guard` (or `claude plugin update 7it-guard@7it-guard` from a terminal). The full report page says so when it was made with an older version.

Needs Node.js 18 or newer. No account. The plugin asks for an optional 7IT key when you enable it; leave it empty unless you have one.

The 7Maps marketplace lists 7IT Guard too, so `/plugin marketplace add XLSV777/7maps` followed by `/plugin install 7it-guard@7maps` installs the same plugin (then turn on auto-update for the `7maps` marketplace, and update by hand with `/plugin marketplace update 7maps`).

### Other agents

The `guard` skill carries its script in its own folder, so it works in other agents that read Agent Skills (Codex, Cursor, GitHub Copilot, Gemini CLI and others), with the same local run and the same rules:

```
npx skills add XLSV777/7it-guard
```

Gemini CLI can install the repository as an extension (`gemini-extension.json` at the root):

```
gemini extensions install https://github.com/XLSV777/7it-guard
```

Outside Claude Code there is no `/7it-guard:check` command and no fix server: ask in your own words ("is my app at myapp.com ready to ship?").

## Use

```
/7it-guard:check myapp.com
```

Or ask in your own words: "is my app ready to ship?", "run a pre-launch check on myapp.com". The `guard` skill picks it up. Claude runs:

```
node skills/guard/scripts/check.mjs myapp.com              # the report as text
node skills/guard/scripts/check.mjs myapp.com --json       # the same, as JSON
node skills/guard/scripts/check.mjs myapp.com --owner      # include the deep checks (your own app, token on it)
node skills/guard/scripts/check.mjs myapp.com --token      # print the ownership token
node skills/guard/scripts/check.mjs myapp.com --no-7maps   # skip the 7Maps lookup of an MCP server the app publishes
```

You can run the script yourself too. A sample terminal report:

```
7IT Guard 0.3.2 · app.example.com · 2026-10-04 · run on this machine, nothing about the app sent to 7IT
Grade D (64/100) · 1 to fix before shipping · 6 to fix soon

  Security        74  ███████░░░  4 issues
  Data exposure    -  not checked: runs only on an app you own (see below)
  Secrets         75  ████████░░  1 issue
  ...
Fix before shipping
   1. HIGH Secrets: A JavaScript source map is public (/assets/index-4f2a.js.map). Stop publishing .map files ...
Fix soon
   2. MED  Security: No Content Security Policy. Add a Content-Security-Policy header ...
...
Full report: https://7it.co.il/tools/guard/report/#r=...
Not checked from outside: load and traffic spikes, scale limits, architecture, business logic behind the login, cost at scale, backups and recovery, compliance. A senior review covers these: https://7it.co.il/services/ai-built-apps/
```

**The full report link** opens a visual report (scores, severity, the fix list with copyable snippets for Vercel, Netlify, Next.js and nginx, SPF and DMARC records, and a print or save-as-PDF button). The results travel inside the link after the `#`, which browsers never send to a server: the page decodes them in your browser. 7IT's server only sends the empty page.

**Deep checks need proof that the app is yours.** The report prints an inert token. Add it to your app as a meta tag on the home page (`<meta name="7it-site-verification" content="7it-verify-...">`) or as a file at `/7it-verify.txt`, deploy, and run the check again with `--owner`. The token runs nothing and can be removed afterwards; the same token also unlocks the deep scan on [7it.co.il/tools/app-security](https://7it.co.il/tools/app-security/). The skill tells Claude to use `--owner` or add a token only when you say the app is yours.

**Fixing:** `/7it-guard:fix` walks through the findings in your repository, most severe first, asking before every change, then checks again. Changes outside the code (rotating a key, database policies, DNS records) are given to you as exact steps to run yourself.

**Backup vault (with a 7IT key whose plan or Vault add-on includes it):** `/7it-guard:vault` sets up a nightly encrypted copy of your database and your stored files into storage you own, plus a weekly restore test, all running in your own GitHub account. It finds what it can in the project (the platform, the database variable, Supabase Storage or an S3 or R2 bucket, the default branch, your time zone) and asks only what it cannot know, such as where the backups should live (a new Cloudflare R2 bucket by default). It writes two complete workflow files (`.github/workflows/7it-vault.yml` and `7it-vault-restore.yml`, every step visible, tools pinned and checked), makes your backup key on your machine and tells you where it is so you can keep it in your password manager, sets the GitHub secrets with `gh secret set`, offers a database sign-in that can only read (shown before it runs, only with your yes), and starts the first backup and restore test. Running it again keeps your keys and updates the files. It needs the GitHub CLI (`gh`). On Lovable Cloud or Bolt Database it writes nothing: those platforms give no database address, so a nightly copy cannot run there. It says so plainly (manual, not automatic) and explains the two paths: move to your own Supabase project (after that the vault works as above), and until then press the platform's own export button once a month, with a monthly reminder in the 7IT Guard app if you want one.

**Optional, Google PageSpeed:** set `PAGESPEED_API_KEY` to your own Google API key in the shell Claude Code runs in. The script then asks Google PageSpeed for the phone performance and accessibility scores (that request goes from your machine to Google and includes the app's address).

## What it sends, and what it never sends

- **Every check runs on your machine.** Requests go from your machine straight to the app you name (its pages, headers, certificate and a few well-known paths), and to public DNS (for the email records). No request ever goes to the app's database (Supabase or Firebase), with or without `--owner`. The report ends with the count of requests and the hosts they went to.
- **Nothing about the app is sent to 7IT** by a check. Not the address, not the results, not your code.
- **The 7Maps lookup** happens only when the app publishes an MCP server. The check then computes the server's 7Maps key and its hash on your machine (SHA-256, first 12 characters, the same scheme 7Maps states in its public lists) and downloads one public list, `https://7it.co.il/7maps/known/<first 2 characters of the hash>.json`: the hashes of the servers on the map that start with those 2 characters (at most 3 such downloads per check). The request carries those 2 characters and `?via=guard`, never the address; the comparison happens on your machine. `--no-7maps` skips it. 7IT counts these downloads (no address, no hash) and keeps the standard host logs.
- **The report link** carries the results in the URL fragment, which browsers do not send to servers. Opening it loads a static page from 7it.co.il; Google Analytics on that page records the page address without the fragment.
- **The 7IT key**, if you set one, is kept in your system's secure storage by Claude Code and handed only to the plugin's small local fix server ([`scripts/fix-server.mjs`](scripts/fix-server.mjs)). It makes no request on its own. When `/7it-guard:fix` asks it for the strict playbook, it makes ONE request to `https://7it.co.il/guard/playbook` with the key, the ids of the findings (for example `csp_missing,no_dmarc`) and the detected platform names (for example `vercel,supabase`). Never the app's address, the report, your code or the conversation. Without a key it makes no request at all. 7IT keeps a usage count per key and a usage record (no report, no address).
- **What a deep check reads**: the response to well-known file paths (first 4 KB, matched on shape, reported as a path, never the content); the app's own scripts (in memory only, to look for key shapes; a key is reported by type and file, never its value); the Supabase project or Firebase config named in that same code (the project address is public; it is used only for the links to your own dashboard). Nothing inside the database: no table names, no counts, no rows, no settings, no file listings. Nothing is written anywhere and nothing is kept.

- **The backup vault** (`/7it-guard:vault`): your data never comes to 7IT. The copy is made, encrypted with your own key and stored in your own storage by the workflow in your own GitHub account. The setup reads the project's env files on your machine and passes secrets straight to `gh secret set`; it never prints them. With your 7IT key, the local fix server makes the registration request to `https://7it.co.il/guard/app/api/vault_setup` with the key, the site's address, the repository's name and numeric id, the branch, the schedule, the time zone and whether stored files are copied (for the monthly export reminder on Lovable Cloud or Bolt Database: only the site's address and the platform's name). Never a database address, a password, a storage key or any private key. After that, each run sends 7IT a short receipt from your workflow (times, sizes, checksums, counts, which dates can be restored, ok or not), proven by GitHub's own identity token for that run.

Privacy policy: https://7it.co.il/privacy/#guard

## One 7IT key

One 7IT key will unlock both 7IT plugins: this plugin's optional setting (`fix_key`, shown as "7IT key (optional)") and the optional key setting of the [7Maps plugin](https://github.com/XLSV777/7maps) (`maps_key`) take the same key. The setting names stay as they are. 7IT Guard works fully without it.

## No Node?

7IT Guard needs Node.js 18 or newer (https://nodejs.org). An MCP client that cannot run Node can use the hosted fallback, `https://7it.co.il/mcp?set=guard`, which runs the public checks on 7IT's server (and then 7IT does receive the address; see the privacy policy).

## Tests

```
node --test tests/check.test.mjs
```

Every network call in the tests goes to a local mock server; DNS and TLS are stubbed.

## Troubleshooting

**Node.js is missing or older than 18** (`node: command not found`, or an error as soon as the check starts). Run `node --version`. Install the current LTS
from https://nodejs.org and open a new terminal, then run the check again. A client that cannot run Node can use the
hosted fallback, `https://7it.co.il/mcp?set=guard` (7IT then receives the address; see the privacy policy).

**"That is not a public web address."** The check runs only against an app the public internet can reach. Local and
private addresses (`localhost`, `127.0.0.1`, `.local`, `.internal`, `.test` and other reserved names) are refused on
purpose. Deploy the app first, then pass its domain (`myapp.com`) or its full `https://` address.

**The check is slow or says a page timed out.** Each request waits at most 12 seconds and the check asks at most 4
things of your app at a time. A host that sleeps when idle (some hosting plans pause an app until the next visit) answers
the first request slowly: open the app once in a browser and run the check again. A site that never answers gets a
Reliability finding, not an error.

**"The app does not answer over HTTPS."** Your host has not issued a certificate yet, or the domain is not connected to
the app. Most hosts issue one by themselves a few minutes after the domain is connected. Check again after that.

**Data exposure says "not checked".** The deep checks run only on your own app, with proof that it is yours. Run
`/7it-guard:check myapp.com --token` (or ask Claude for the ownership token), add it to your app as a meta tag on the
home page or as the file `/7it-verify.txt`, deploy, then run the check again with `--owner`.

**The ownership token is not found.** The meta tag must be in the HTML the server sends, not added later by
JavaScript: in a single-page app, put it in `index.html` (or the root layout), not in a component. A file goes in the
folder your host serves as is (often `public/`). After a deploy, a cache can keep the old page for a minute or two: wait,
then check again. The token runs nothing and can be removed afterwards.

**The "Full report" link does not open the whole report.** The results travel inside the link after `#`, so very long
reports are shortened (the fix sentences first, then the low items). Every finding is still in the terminal report, and
`--json` prints all of it.

**No Google PageSpeed scores.** They appear only with your own Google API key in `PAGESPEED_API_KEY`, set in the shell
Claude Code runs in. Without a key, or when Google's limit for the key is reached, the rest of the check runs as usual.

**The check downloaded a list from 7it.co.il.** That happens only when your app publishes an MCP server: the check
looks up whether it is on 7Maps, with 2 characters of a hash, never your address. `--no-7maps` skips it.

**`/7it-guard:fix` or `/7it-guard:vault` asks for a 7IT key.** The key is optional for the check and for fix (fix then
works from the report alone). The vault needs a key whose plan includes it. Set or change the key in the plugin's
settings ("7IT key (optional)").

### When the 7IT Guard app (the watch from outside) says no or not yet

The check on your own machine never depends on these: it keeps working as usual in every case below.

- **"Guard is watching as many sites as it can take right now, so ... was not added."** The watch is at its limit of
  sites for the moment. More places open as capacity is added, usually within a day. Nothing was stored; try again
  tomorrow.
- **"... is in line. Guard starts watching it within about N hours"** (or "as soon as a place opens"). Many sites joined
  at once. The site is verified and kept; Guard starts watching it by itself. Nothing to do.
- **"Today's places for Guard Pro on us are taken."** The site is watched once an hour meanwhile, and Guard Pro on us
  starts by itself as a place opens, usually within a few days.
- **"Guard reached its own daily limit for checks, so checks are paused until midnight UTC."** Checks start again by
  themselves after midnight UTC. Nothing is lost.
- **"Many new sign-ups came from this network today."** New sites from that network are paused until midnight UTC. Try
  again after that, or from another network.
- **"Signing in on a new device is slowed" or "paused for now."** Many sign-in attempts failed in a short time. Try again
  in about 10 minutes (slowed) or a few hours (paused), or use a device that is already signed in.
- **"This domain already has the most sites Guard watches for one owner."** Remove one of them in the app, then add the
  new one.

### Still stuck?

Open an issue at https://github.com/XLSV777/7it-guard/issues with the plugin version (the first line of the report), the
output of `node --version`, the command you ran, and the message you saw. Leave out keys, tokens and anything private:
the address of your app is enough, and only if you are fine with it being public.

## Uninstall

```
/plugin uninstall 7it-guard@7it-guard
/plugin marketplace remove 7it-guard
```

If you added an ownership token to your app, remove the meta tag or the `/7it-verify.txt` file; nothing else is left behind.

If you set up the backup vault, it lives in your repository and keeps running after the plugin is gone. To stop it, delete `.github/workflows/7it-vault.yml` and `7it-vault-restore.yml` and the `VAULT_` secrets of the repository; your backups stay in your storage.

If you installed it from the 7Maps marketplace, use `/plugin uninstall 7it-guard@7maps` instead (the 7Maps plugin stays).

## Limits

7IT Guard sees what the public internet sees. It is not a penetration test, it cannot see pages behind a login, and automated accessibility checks cover only part of WCAG. Load, scale, architecture, the logic behind the login, cost, backups and compliance are out of its sight. Treat the report as the first pass before launch, not a guarantee.

Formerly named Ship Check. Not the same as `7maps-guard`, the 7Maps client middleware for MCP clients.

By [7IT](https://7it.co.il/). MIT license.
