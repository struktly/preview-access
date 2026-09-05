import { env } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import {
  activateRequestStatement,
  activeDownloaderQuery,
  claimTokenHash,
  declineRequestStatement,
  newClaimToken,
  redeemClaimStatement,
  revokeAccessStatement,
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

const REQUESTED = "tester@work.example";
const GITHUB_IDENTITY = "tester@personal.example";

async function approve(login = "octocat"): Promise<string> {
  const token = newClaimToken();
  const activated = await env.DB.prepare(activateRequestStatement)
    .bind(login, await claimTokenHash(token))
    .first<{ email: string }>();
  expect(activated?.email).toBe(REQUESTED);
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

function decline(login = "octocat") {
  return env.DB.prepare(declineRequestStatement).bind(login).first();
}

function revoke(login = "octocat") {
  return env.DB.prepare(revokeAccessStatement).bind(login).first();
}

describe("claiming an approval", () => {
  beforeEach(async () => {
    await env.DB.prepare("DROP TABLE IF EXISTS access_requests").run();
    await env.DB.prepare(SCHEMA).run();
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
    expect(await redeem(newClaimToken())).toBeNull();
  });

  it("writes an expiry in the format the redemption compares against", async () => {
    const token = await approve();
    const row = await env.DB.prepare(
      "SELECT claim_expires_at, claim_expires_at > CURRENT_TIMESTAMP AS live FROM access_requests",
    ).first<{ claim_expires_at: string; live: number }>();

    expect(row?.claim_expires_at).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    expect(row?.live).toBe(1);

    await env.DB.prepare(
      "UPDATE access_requests SET claim_expires_at = datetime('now', '-1 second')",
    ).run();
    expect(await redeem(token)).toBeNull();
  });

  it("will not approve, or hand a token to, a request that is not pending", async () => {
    await approve();
    const second = newClaimToken();
    expect(
      await env.DB.prepare(activateRequestStatement)
        .bind("octocat", await claimTokenHash(second))
        .first(),
    ).toBeNull();
    expect(await redeem(second)).toBeNull();
  });

  it("keeps a removed approval out of the gate after it was claimed", async () => {
    const token = await approve();
    await redeem(token);
    expect(await revoke()).not.toBeNull();

    expect(await mayDownload(GITHUB_IDENTITY)).toBeNull();
    expect(await mayDownload(REQUESTED)).toBeNull();
  });

  it("kills an unredeemed claim link when access is removed", async () => {
    const token = await approve();
    expect(await revoke()).not.toBeNull();

    expect(await redeem(token)).toBeNull();
    expect(await mayDownload(GITHUB_IDENTITY)).toBeNull();
  });

  it("removes only active access, and declines only a pending request", async () => {
    expect(await revoke()).toBeNull();
    expect(await decline()).not.toBeNull();
    expect(await decline()).toBeNull();
    expect(await mayDownload(REQUESTED)).toBeNull();
  });

  it("lets a declined or removed decision be reversed, on a fresh link only", async () => {
    await decline();
    const first = await approve();
    expect(await mayDownload(REQUESTED)).not.toBeNull();

    await redeem(first);
    await revoke();
    const second = await approve();

    expect(await redeem(first)).toBeNull();
    expect(await mayDownload(GITHUB_IDENTITY)).toBeNull();
    expect(await redeem(second)).not.toBeNull();
    expect(await mayDownload(GITHUB_IDENTITY)).not.toBeNull();
  });
});
