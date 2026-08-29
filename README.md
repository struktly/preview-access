# Struktly preview access

[![Checks](https://github.com/struktly/preview-access/actions/workflows/checks.yml/badge.svg)](https://github.com/struktly/preview-access/actions/workflows/checks.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020.svg)](https://workers.cloudflare.com/)

A tiny approval and download service for preview builds without GitHub
collaborator seats.

1. Open the private page.
2. Click **Approve**.
3. The tester signs in at the download page and gets the approved builds.

The source is public. Request data and administrator identity stay private in
Cloudflare D1 and Cloudflare Access. Release files stay in a private R2 bucket.
The page never displays emails or use-case text, and logs only result states.

## How it works

Cloudflare Access protects both hostnames. The founder-only hostname approves a
pending request in D1. The downloads hostname first verifies a separate Access
identity and then serves R2 files only when that exact email has active preview
access in D1. Repeating approval is safe.

The Worker is unavailable on `workers.dev`. The private Struktly infrastructure
repository owns its custom domain and Cloudflare Access policy through
OpenTofu; this repository owns only the runtime deployment.

## Development

```sh
npm install
npm run check
```

## Deploying your own copy

Create the two hostnames, Access applications, and R2 bucket in your
infrastructure stack. Set the account, database, team domain, and founder
Access audience in `wrangler.jsonc`. Set these Worker secrets before deploying:

```sh
npx wrangler secret put ADMIN_EMAIL
npx wrangler secret put DOWNLOADS_ACCESS_AUD
npm run deploy
```

`DOWNLOADS_ACCESS_AUD` is the Terraform output for the downloads Access
application. The production deploy helper reads it from the encrypted
infrastructure state configuration; it is not a GitHub credential.
