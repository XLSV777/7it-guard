# Ship Check

Docs: https://7it.co.il/tools/ship-check/

A Claude Code plugin that checks a deployed web app from the outside before it ships, and returns one prioritized list of what to fix first. Made for apps built with AI tools (Lovable, Replit, Bolt, v0, Cursor, Claude Code), and works for any app at a public address.

One call checks:

- **Security headers**: Content Security Policy, HTTPS enforcement, clickjacking and MIME-sniffing protection, referrer and permissions policy, cross-origin isolation.
- **A public source map**: whether anyone can read the app's original source code.
- **Phone speed**: Google PageSpeed on a phone, with the biggest gains.
- **Email authentication** of the app's domain: SPF, DKIM and DMARC (skipped on shared platform addresses such as `myapp.lovable.app`).
- **Accessibility**: Lighthouse's automated WCAG checks.
- **Exposed files and the backend**, on an app whose ownership is proven: an `.env` file, a `.git` folder, a directory listing, and what an anonymous visitor can read in the app's Supabase or Firebase project (table and bucket names with row counts, never contents or keys).

The report has two lists, "Fix before shipping" (something is exposed now) and "Fix soon" (hardening, speed, accessibility, email), plus links to a full report for each area.

## Install

```
/plugin marketplace add XLSV777/shipcheck
/plugin install shipcheck@shipcheck
```

Nothing to set up: no account, no key.

## Use

```
/shipcheck:check myapp.com
```

Or ask in your own words: "is my app ready to ship?", "run a pre-launch check on myapp.com". The `ship-check` skill picks it up.

**Deep checks need proof of ownership.** The first report ends with an inert token. Add it to your app as a meta tag on the home page (`<meta name="7it-site-verification" content="...">`) or as a file at `/7it-verify.txt`, deploy, and run the check again: the second report includes exposed files and the database. The token runs nothing and can be removed afterwards. This gate is why the deep checks can never be pointed at someone else's app; the skill tells Claude to add a token only when you say the app is yours.

After a fix, Claude re-checks only that area with one of the single tools (`check_app_security`, `deep_scan_app`, `test_store_speed`, `check_email_authentication`, `check_accessibility`).

## What it sends, and what it never sends

The plugin is one MCP server entry (`.mcp.json`) pointing at `https://7it.co.il/mcp?via=shipcheck-plugin&set=shipcheck`, a skill and a command. It has no hooks and runs nothing on your machine.

- **Sent**: the address of the app you ask to check, and the tool name. Like every MCP call, the request also carries your MCP client's name and version.
- **Never sent**: your code, files, environment variables, keys, conversation or any other part of your project.
- **What 7IT keeps**: a usage record per call (the tool, the app's host name, the client, the country derived from the connection and a pseudonymous id that changes every year; never the IP address), kept 90 days. The speed result is kept up to 24 hours so its report link works. 7IT's owner gets a short notice of which tool was used and the address it checked. Deep scan findings are reported as paths, names and counts; no file contents, table rows or key values are read into or stored by 7IT.
- **What the checks touch**: the app's public pages and headers, Google PageSpeed (which loads the page like a phone), public DNS records, and, after verification only, a fixed list of well-known file paths and the backend's public API with the app's own public key, read-only.

Privacy policy: https://7it.co.il/privacy/#ship-check

## Uninstall

```
/plugin uninstall shipcheck@shipcheck
/plugin marketplace remove shipcheck
```

If you added a verification token to your app, remove the meta tag or the `/7it-verify.txt` file; nothing else is left behind.

## Limits

Ship Check sees what the public internet sees. It is not a penetration test, it cannot see pages behind a login, and automated accessibility checks cover only part of WCAG. Treat the report as the first pass before launch, not a guarantee.

By [7IT](https://7it.co.il/). MIT license.
