# Struktly preview access

[![Checks](https://github.com/struktly/preview-access/actions/workflows/checks.yml/badge.svg)](https://github.com/struktly/preview-access/actions/workflows/checks.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/runtime-Cloudflare%20Workers-f38020.svg)](https://workers.cloudflare.com/)

The tester-facing gate for preview builds, without GitHub collaborator seats.

1. An approved tester opens the single-use verification link they were mailed
   and signs in with a one-time PIN or with GitHub.
2. That sign-in is bound to their approval.
3. They get the approved builds, and each download is recorded.

The source is public. Request data and tester identities stay private in
Cloudflare D1 and Cloudflare Access. Release files stay in a private R2 bucket.
The page never displays emails, and logs only result states.

Approving, declining, and removing testers, and the mail that carries the
verification link, live in a separate private Worker. Nothing founder-facing
and no sending credential is in this repository or its Worker.

## How it works

Cloudflare Access protects the download hostname and establishes a signed-in
identity; it deliberately allows everyone, because authorization happens here.
The Worker serves R2 files only when that identity has active preview access
in D1.

Approval is keyed on a GitHub username; this gate is keyed on the address
Cloudflare Access reports. Those disagree whenever someone signs in through an
identity provider carrying a different address than the one they requested
with, which is the normal case for GitHub sign-in. So approval mails a
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
Worker's secret is already seeded, and uploads — on a Worker-upload-only
Cloudflare token that cannot read D1, write R2, or touch Access policy.

`DOWNLOADS_ACCESS_AUD` is deliberately not a GitHub secret. `wrangler deploy`
preserves it, and the private Struktly infrastructure repository stays the only
thing that writes it:

```sh
make deploy-preview-access
```

That is the local handle. Run it to seed a Worker that has never been deployed,
or when the Access audience changes; the deploy workflow refuses to publish a
Worker whose secret is missing rather than shipping one that would deny
everybody.

## Deploying your own copy

Create the download hostname, its Access application, and the R2 bucket in your
infrastructure stack, and a private Worker of your own for approvals. Set the
account, database, and team domain in `wrangler.jsonc`. Set this Worker secret
before deploying:

```sh
npx wrangler secret put DOWNLOADS_ACCESS_AUD
npm run deploy
```

`DOWNLOADS_ACCESS_AUD` is the Terraform output for the downloads Access
application. The production deploy helper reads it from the encrypted
infrastructure state configuration; it is not a GitHub credential.
