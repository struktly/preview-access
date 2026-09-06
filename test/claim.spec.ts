import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import {
  activeDownloaderQuery,
  claimTokenHash,
  recordDownloadStatement,
  redeemClaimStatement,
} from "../src/core.js";

// The Worker binds a database the website repository migrates, so the schema
// here is the shape those migrations produce. It exists to run the Worker's own
// statements: the expiry format, the single-use redemption and the widened gate
// are all decided by SQL, and none of them fail loudly when they are wrong.
const SCHEMA = `
  CREATE TABLE access_requests (
    email TEXT PRIMARY KEY COLLATE NOCASE,
    platform TEXT NOT NULL CHECK (platform IN ('macos', 'linux', 'both')),
    use_case TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    github_login TEXT COLLATE NOCASE,
    access_status TEXT NOT NULL DEFAULT 'pending',
    approved_at TEXT,
    invited_at TEXT,
    active_at TEXT,
    revoked_at TEXT,
    claim_token_hash TEXT,
    claim_expires_at TEXT,
    claimed_email TEXT COLLATE NOCASE,
    claimed_at TEXT
  ) WITHOUT ROWID`;

// The indexes website's migrations 0002 and 0003 put on the live table. The
// single-token-per-approval property the claim route rests on is the unique
// index, so a test table without it would stay green while the production
// constraint was gone.
const INDEXES = [
  `CREATE UNIQUE INDEX access_requests_github_login_unique
    ON access_requests(github_login)
    WHERE github_login IS NOT NULL`,
  `CREATE UNIQUE INDEX access_requests_claim_token_hash_unique
    ON access_requests(claim_token_hash)
    WHERE claim_token_hash IS NOT NULL`,
  `CREATE INDEX access_requests_claimed_email
    ON access_requests(claimed_email)
    WHERE claimed_email IS NOT NULL`,
];

const DOWNLOADS_SCHEMA = `
  CREATE TABLE downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity TEXT NOT NULL COLLATE NOCASE,
    release_tag TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    downloaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`;

const REQUESTED = "tester@work.example";
const GITHUB_IDENTITY = "tester@personal.example";

function mintToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// What the admin Worker's approval writes. Its statement is tested in that
// repository; here it is a fixture for the rows the gate then has to judge.
async function approve(): Promise<string> {
  const token = mintToken();
  await env.DB.prepare(
    `UPDATE access_requests
     SET access_status = 'active',
         claim_token_hash = ?1,
         claim_expires_at = datetime('now', '+14 days')
     WHERE email = ?2`,
  ).bind(await claimTokenHash(token), REQUESTED).run();
  return token;
}

function redeem(token: string, identity = GITHUB_IDENTITY) {
  return claimTokenHash(token).then((hash) =>
    env.DB.prepare(redeemClaimStatement).bind(hash, identity).first(),
  );
}

function mayDownload(identity: string) {
  return env.DB.prepare(activeDownloaderQuery).bind(identity).first();
}

describe("claiming an approval", () => {
  beforeEach(async () => {
    await env.DB.prepare("DROP TABLE IF EXISTS access_requests").run();
    await env.DB.prepare("DROP TABLE IF EXISTS downloads").run();
    for (const statement of [SCHEMA, ...INDEXES, DOWNLOADS_SCHEMA]) {
      await env.DB.prepare(statement).run();
    }
    await env.DB.prepare(
      `INSERT INTO access_requests (email, github_login, platform) VALUES (?1, 'octocat', 'both')`,
    ).bind(REQUESTED).run();
  });

  it("lets a sign-in that carries another address through, once it is claimed", async () => {
    const token = await approve();

    expect(await mayDownload(REQUESTED)).not.toBeNull();
    expect(await mayDownload(GITHUB_IDENTITY)).toBeNull();

    expect(await redeem(token)).not.toBeNull();

    expect(await mayDownload(GITHUB_IDENTITY)).not.toBeNull();
    expect(await mayDownload("TESTER@Personal.Example")).not.toBeNull();
    expect(await mayDownload(REQUESTED)).not.toBeNull();
    expect(await mayDownload("someone@else.example")).toBeNull();
  });

  it("spends the token on first use", async () => {
    const token = await approve();
    expect(await redeem(token)).not.toBeNull();
    expect(await redeem(token, "attacker@else.example")).toBeNull();
    expect(await mayDownload("attacker@else.example")).toBeNull();
  });

  it("refuses a token that was never minted", async () => {
    await approve();
    expect(await redeem(mintToken())).toBeNull();
  });

  it("refuses a token past its expiry", async () => {
    const token = await approve();
    await env.DB.prepare(
      "UPDATE access_requests SET claim_expires_at = datetime('now', '-1 second')",
    ).run();
    expect(await redeem(token)).toBeNull();
  });

  it("keeps a removed approval out of the gate, claimed or not", async () => {
    const token = await approve();
    await redeem(token);
    await env.DB.prepare(
      "UPDATE access_requests SET access_status = 'revoked', claim_token_hash = NULL, claim_expires_at = NULL",
    ).run();

    expect(await mayDownload(GITHUB_IDENTITY)).toBeNull();
    expect(await mayDownload(REQUESTED)).toBeNull();
    expect(await redeem(token)).toBeNull();
  });

  it("records a served asset against the identity that fetched it", async () => {
    await env.DB.prepare(recordDownloadStatement)
      .bind(GITHUB_IDENTITY, "v0.1.35", "Struktly_0.1.35_aarch64.dmg")
      .run();
    const row = await env.DB.prepare(
      "SELECT identity, release_tag, asset_id, downloaded_at FROM downloads",
    ).first<{ identity: string; release_tag: string; asset_id: string; downloaded_at: string }>();

    expect(row?.identity).toBe(GITHUB_IDENTITY);
    expect(row?.release_tag).toBe("v0.1.35");
    expect(row?.asset_id).toBe("Struktly_0.1.35_aarch64.dmg");
    expect(row?.downloaded_at).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });
});
