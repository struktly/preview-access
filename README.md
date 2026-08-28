# Struktly preview access

[![Checks](https://github.com/struktly/preview-access/actions/workflows/checks.yml/badge.svg)](https://github.com/struktly/preview-access/actions/workflows/checks.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020.svg)](https://workers.cloudflare.com/)

A tiny admin page for approving preview access without GitHub Actions or a
local Cloudflare token.

1. Open the private page.
2. Click **Approve**.
3. The tester gets read-only access to release builds.

The source is public. The request data, administrator identity, GitHub App key,
and release repository stay private in Cloudflare D1, Cloudflare Access, and
Worker secrets. The page never displays emails or use-case text, and logs only
the result state.

## How it works

Cloudflare Access admits the administrator and the Worker verifies that signed
identity again. The Worker reads only pending macOS requests through its D1
binding, mints a short-lived token from a repository-scoped GitHub App, sends a
read-only invitation, and records the result. Repeating the click is safe.

The Worker is unavailable on `workers.dev`; only the Access-protected custom
domain is deployed.

## Development

```sh
npm install
npm run check
```

## Deploying your own copy

Update the non-secret account, database, hostname, team-domain, and Access AUD
values in `wrangler.jsonc`. Then set these Worker secrets:

```sh
npx wrangler secret put ADMIN_EMAIL
npx wrangler secret put GITHUB_APP_ID
npx wrangler secret put GITHUB_APP_PRIVATE_KEY
npx wrangler secret put RELEASES_REPO
npm run deploy
```

The GitHub App should be installed on exactly one private artifact repository
with only `Administration: read and write`. That permission is required by
GitHub to invite a read-only collaborator; installation tokens are restricted
to that repository and expire automatically.
