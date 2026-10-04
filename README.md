# Ship Check

Docs: https://7it.co.il/tools/ship-check/

A Claude Code plugin that checks a deployed web app from the outside before it ships, **on your own machine**, and returns one graded, prioritized list of what to fix first. Made for apps built with AI tools (Lovable, Replit, Bolt, v0, Cursor, Claude Code), and works for any app at a public address.

The check is one readable Node script, [`scripts/shipcheck.mjs`](scripts/shipcheck.mjs): Node 18 or newer, built-in modules only, no dependencies, nothing to install.

## What it checks

Eight categories, each scored out of 100, an overall grade (A to F; anything exposed right now caps it), and severity on every finding:

- **Security**: HTTPS and the http-to-https redirect, HSTS, Content Security Policy (and whether it still allows inline scripts), clickjacking protection, nosniff, referrer and permissions policy, cross-origin isolation, cookie flags, mixed content, version banners, security.txt.
- **Secrets**: a public JavaScript source map; on your own app, also keys shaped like OpenAI, Anthropic, Stripe, GitHub, AWS, SendGrid, Slack and other secret keys in the code sent to browsers, and a Supabase service role key.
- **Data exposure** (your own app only): `.env` files, a `.git` folder, backups, admin tools and directory listings; what an anonymous visitor can read in the app's Supabase project (table and bucket names with row counts, open sign-up) or Firebase project (open Realtime Database, listable storage).
- **Email**: SPF, DMARC and DKIM (common selectors) of the app's domain, from public DNS. Skipped on shared platform addresses such as `myapp.lovable.app`.
- **Performance**: time to first byte, HTML weight, compression, script count and weight, render-blocking scripts, caching of versioned files. Google PageSpeed scores too, if you set your own key (below).
- **Accessibility** (from the HTML): page language, image text alternatives, form labels, button and link names, zoom, main heading and landmark. Colour contrast and keyboard use cannot be checked from outside; the report says so.
- **SEO**: title, meta description, canonical, Open Graph, noindex left on, robots.txt, sitemap.
- **Reliability**: home page status, certificate validity and expiry, redirect chain, real 404s, www and the bare domain.

## Install

```
/plugin marketplace add XLSV777/shipcheck
/plugin install shipcheck@shipcheck
```

Needs Node.js 18 or newer. No account. The plugin asks for an optional fix key when you enable it; leave it empty unless you have one.

## Use

```
/shipcheck:check myapp.com
```

Or ask in your own words: "is my app ready to ship?", "run a pre-launch check on myapp.com". The `ship-check` skill picks it up. Claude runs:

```
node scripts/shipcheck.mjs myapp.com            # the report as text
node scripts/shipcheck.mjs myapp.com --json     # the same, as JSON
node scripts/shipcheck.mjs myapp.com --owner    # include the deep checks (your own app, token on it)
node scripts/shipcheck.mjs myapp.com --token    # print the ownership token
```

You can run the script yourself too. A sample terminal report:

```
Ship Check 0.2.0 · app.example.com · 2026-10-04 · run on this machine, nothing sent to 7IT
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
Full report: https://7it.co.il/tools/ship-check/report/#r=...
Not checked from outside: load and traffic spikes, scale limits, architecture, business logic behind the login, cost at scale, backups and recovery, compliance. A senior review covers these: https://7it.co.il/services/ai-built-apps/
```

**The full report link** opens a visual report (scores, severity, the fix list with copyable snippets for Vercel, Netlify, Next.js and nginx, SPF and DMARC records, Supabase row level security policies, and a print or save-as-PDF button). The results travel inside the link after the `#`, which browsers never send to a server: the page decodes them in your browser. 7IT's server only sends the empty page.

**Deep checks need proof that the app is yours.** The report prints an inert token. Add it to your app as a meta tag on the home page (`<meta name="7it-site-verification" content="7it-verify-...">`) or as a file at `/7it-verify.txt`, deploy, and run the check again with `--owner`. The token runs nothing and can be removed afterwards; the same token also unlocks the deep scan on [7it.co.il/tools/app-security](https://7it.co.il/tools/app-security/). The skill tells Claude to use `--owner` or add a token only when you say the app is yours.

**Fixing:** `/shipcheck:fix` walks through the findings in your repository, most severe first, asking before every change, then checks again. Changes outside the code (rotating a key, database policies, DNS records) are given to you as exact steps to run yourself.

**Optional, Google PageSpeed:** set `PAGESPEED_API_KEY` to your own Google API key in the shell Claude Code runs in. The script then asks Google PageSpeed for the phone performance and accessibility scores (that request goes from your machine to Google and includes the app's address).

## What it sends, and what it never sends

- **Every check runs on your machine.** Requests go from your machine straight to the app you name (its pages, headers, certificate and a few well-known paths), to public DNS (for the email records), and, with `--owner` on an app that carries the token, to the Supabase or Firebase project the app's own browser code points at, using the app's own public key, read-only. The report ends with the count of requests and the hosts they went to.
- **Nothing is sent to 7IT** by a check. Not the address, not the results, not your code.
- **The report link** carries the results in the URL fragment, which browsers do not send to servers. Opening it loads a static page from 7it.co.il; Google Analytics on that page records the page address without the fragment.
- **The fix key**, if you set one, is kept in your system's secure storage by Claude Code and handed only to the plugin's small local fix server ([`scripts/fix-server.mjs`](scripts/fix-server.mjs)). It makes no request on its own. When `/shipcheck:fix` asks it for the strict playbook, it makes ONE request to `https://7it.co.il/shipcheck/playbook` with the key, the ids of the findings (for example `csp_missing,no_dmarc`) and the detected platform names (for example `vercel,supabase`). Never the app's address, the report, your code or the conversation. Without a key it makes no request at all. 7IT keeps a usage count per key and a usage record (no report, no address).
- **What a deep check reads**: the response to well-known file paths (first 4 KB, matched on shape, reported as a path, never the content); the app's own scripts (in memory only, to look for key shapes; a key is reported by type and file, never its value); Supabase table names from the API schema and a count-only request per table (never a row); storage bucket listings limited to one item, reported as the bucket name; Firebase Realtime Database key count. Nothing is written anywhere and nothing is kept.

Privacy policy: https://7it.co.il/privacy/#ship-check

## No Node?

Ship Check needs Node.js 18 or newer (https://nodejs.org). An MCP client that cannot run Node can use the hosted fallback, `https://7it.co.il/mcp?set=shipcheck`, which runs the public checks on 7IT's server (and then 7IT does receive the address; see the privacy policy).

## Tests

```
node --test tests/
```

Every network call in the tests goes to a local mock server; DNS and TLS are stubbed.

## Uninstall

```
/plugin uninstall shipcheck@shipcheck
/plugin marketplace remove shipcheck
```

If you added an ownership token to your app, remove the meta tag or the `/7it-verify.txt` file; nothing else is left behind.

## Limits

Ship Check sees what the public internet sees. It is not a penetration test, it cannot see pages behind a login, and automated accessibility checks cover only part of WCAG. Load, scale, architecture, the logic behind the login, cost, backups and compliance are out of its sight. Treat the report as the first pass before launch, not a guarantee.

By [7IT](https://7it.co.il/). MIT license.
