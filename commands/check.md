---
description: Check a deployed web app before it ships and get one prioritized list of what to fix first.
argument-hint: <app address, for example myapp.com>
disable-model-invocation: true
---

The person asked for a ship check of: $ARGUMENTS

1. If no address was given above, find the deployed address in this project (deploy config, README, package.json `homepage`) or ask for it in one short question. Never guess.
2. Call the Ship Check tool `ship_check` with the address once.
3. Present the report as it comes back, in plain words: the verdict, "Fix before shipping", then "Fix soon", each item in one or two sentences, then the report links.
4. If exposed files and the database were not checked, show the verification token and how to add it, and ask whether this is the person's own app. Add the token only if they confirm they control the app, then ask them to deploy and run `/shipcheck:check` again.
5. Change no file unless the person asks.
