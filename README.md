# Struktly preview access

[![Checks](https://github.com/struktly/preview-access/actions/workflows/checks.yml/badge.svg)](https://github.com/struktly/preview-access/actions/workflows/checks.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020.svg)](https://workers.cloudflare.com/)

A tiny approval and download service for preview builds without GitHub
collaborator seats.

1. Open the private page.
2. Click **Approve**. The tester is emailed a single-use verification link.
   **Decline** closes a request without mail; **Remove** ends active access.
3. The tester opens that link, signs in with a one-time PIN or with GitHub, and
   gets the approved builds.

The source is public. Request data and administrator identity stay private in
Cloudflare D1 and Cloudflare Access. Release files stay in a private R2 bucket.
The page never displays emails or use-case text, and logs only result states.

## How it works

Cloudflare Access protects both hostnames. The founder-only hostname approves a
pending request in D1. The downloads hostname first verifies a separate Access
identity and then serves R2 files only when that identity has active preview
access in D1. Repeating approval is safe.

Approval is keyed on a GitHub username; the download gate is keyed on the
address Cloudflare Access reports. Those disagree whenever someone signs in
through an identity provider carrying a different address than the one they
requested with, which is the normal case for GitHub sign-in. So approval mails a
single-use claim link, and `/claim` binds whichever Access identity opens it to
that approval. Reaching the mailbox is the proof; the login method after that is
the tester's choice. Only the SHA-256 of the token is stored, it expires in
fourteen days, and it is cleared the moment it is redeemed.

The Worker is unavailable on `workers.dev`. The private Struktly infrastructure
repository owns its custom domain and Cloudflare Access policy through
OpenTofu; this repository owns only the runtime deployment.

## Development

```sh
npm install
npm run check
```

## Deploying

Pushing to `main` deploys. The workflow runs `npm run check`, proves the
Worker's secrets are already seeded, and uploads — on a Worker-upload-only
Cloudflare token that cannot read D1, write R2, or touch Access policy.

`ADMIN_EMAIL` and `DOWNLOADS_ACCESS_AUD` are deliberately not GitHub secrets.
`wrangler deploy` preserves them, so this public repository never holds the
administrator's address, and the private Struktly infrastructure repository
stays the only thing that writes them:

```sh
make deploy-preview-access
```

That is the local handle. Run it to seed a Worker that has never been deployed,
or when the administrator email or the Access audience changes; the deploy
workflow refuses to publish a Worker whose secrets are missing rather than
shipping one that would deny everybody.

## Deploying your own copy

Create the two hostnames, Access applications, and R2 bucket in your
infrastructure stack. Approval mail goes through [Resend](https://resend.com):
add your sending domain there, publish the DNS records it emits, and create an
API key restricted to sending from that domain. Set the account, database, team
domain, founder Access audience, and sender address in `wrangler.jsonc`. Set
these Worker secrets before deploying:

```sh
npx wrangler secret put ADMIN_EMAIL
npx wrangler secret put DOWNLOADS_ACCESS_AUD
npx wrangler secret put RESEND_API_KEY
npm run deploy
```

`DOWNLOADS_ACCESS_AUD` is the Terraform output for the downloads Access
application. The production deploy helper reads it from the encrypted
infrastructure state configuration; it is not a GitHub credential.
