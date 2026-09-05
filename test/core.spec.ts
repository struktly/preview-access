import { describe, expect, it } from "vitest";
import {
  approvalEmail,
  claimTokenHash,
  claimTokenPattern,
  claimUrl,
  downloadsOrigin,
  escapeHtml,
  githubLoginPattern,
  hasPreviewAccessOrigin,
  newClaimToken,
  parseReleaseManifest,
  previewAccessOrigin,
} from "../src/core.js";

describe("public input boundaries", () => {
  it("accepts valid GitHub usernames and rejects malformed ones", () => {
    expect(githubLoginPattern.test("n1dre")).toBe(true);
    expect(githubLoginPattern.test("valid-user")).toBe(true);
    expect(githubLoginPattern.test("-invalid")).toBe(false);
    expect(githubLoginPattern.test("invalid/user")).toBe(false);
  });

  it("keeps an unlabelled manifest readable and rejects a label with control characters", () => {
    const unlabelled = {
      version: 1,
      tag: "v0.1.35",
      assets: [{
        id: "Struktly_0.1.35_aarch64.dmg",
        name: "Struktly_0.1.35_aarch64.dmg",
        key: "releases/v0.1.35/Struktly_0.1.35_aarch64.dmg",
      }],
    };
    expect(parseReleaseManifest(unlabelled).assets[0].label).toBeUndefined();
    expect(parseReleaseManifest({
      ...unlabelled,
      assets: [{ ...unlabelled.assets[0], label: "Linux · x86-64 (.deb)" }],
    }).assets[0].label).toBe("Linux · x86-64 (.deb)");
    expect(() => parseReleaseManifest({
      ...unlabelled,
      assets: [{ ...unlabelled.assets[0], label: "macOS\u0000injected" }],
    })).toThrow("Invalid release manifest");
  });

  it("accepts a manifest that cannot address arbitrary R2 objects", () => {
    expect(parseReleaseManifest({
      version: 1,
      tag: "v0.1.35",
      assets: [{
        id: "macos-arm64",
        name: "Struktly_0.1.35_aarch64.dmg",
        key: "releases/v0.1.35/Struktly_0.1.35_aarch64.dmg",
      }],
    })).toEqual({
      version: 1,
      tag: "v0.1.35",
      assets: [{
        id: "macos-arm64",
        name: "Struktly_0.1.35_aarch64.dmg",
        key: "releases/v0.1.35/Struktly_0.1.35_aarch64.dmg",
      }],
    });
    expect(() => parseReleaseManifest({
      version: 1,
      tag: "v0.1.35",
      assets: [{ id: "anything", name: "release.dmg", key: "private/secret" }],
    })).toThrow("Invalid release manifest");
  });

  it("drops one unusable asset instead of closing the page on every tester", () => {
    const warnings: unknown[] = [];
    const warn = console.warn;
    console.warn = (...args: unknown[]) => { warnings.push(args[0]); };
    try {
      expect(parseReleaseManifest({
        version: 1,
        tag: "v0.1.35",
        assets: [
          // A publisher that put the file name in the id: legal as a name, not as an id.
          {
            id: "Struktly 0.1.35 aarch64.dmg",
            name: "Struktly 0.1.35 aarch64.dmg",
            key: "releases/v0.1.35/Struktly 0.1.35 aarch64.dmg",
          },
          {
            id: "Struktly_0.1.35_amd64.deb",
            name: "Struktly_0.1.35_amd64.deb",
            key: "releases/v0.1.35/Struktly_0.1.35_amd64.deb",
          },
        ],
      }).assets).toEqual([{
        id: "Struktly_0.1.35_amd64.deb",
        name: "Struktly_0.1.35_amd64.deb",
        key: "releases/v0.1.35/Struktly_0.1.35_amd64.deb",
      }]);
    } finally {
      console.warn = warn;
    }
    expect(warnings).toEqual(["Release manifest v0.1.35: skipped an asset (unusable id)"]);
  });

  it("escapes every HTML-significant character", () => {
    expect(escapeHtml(`<a href='x'>&"`)).toBe("&lt;a href=&#39;x&#39;&gt;&amp;&quot;");
  });

  it("accepts POSTs only from the public approval origin", () => {
    expect(hasPreviewAccessOrigin(new Request("https://internal-worker.example/approve", {
      headers: { Origin: previewAccessOrigin },
    }))).toBe(true);
    expect(hasPreviewAccessOrigin(new Request("https://internal-worker.example/approve", {
      headers: { Referer: `${previewAccessOrigin}/` },
    }))).toBe(true);
    expect(hasPreviewAccessOrigin(new Request("https://internal-worker.example/approve", {
      headers: {
        Origin: "null",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-User": "?1",
      },
    }))).toBe(true);
    expect(hasPreviewAccessOrigin(new Request(previewAccessOrigin, {
      headers: { Origin: "https://attacker.example" },
    }))).toBe(false);
    expect(hasPreviewAccessOrigin(new Request(previewAccessOrigin, {
      headers: { Origin: "null" },
    }))).toBe(false);
  });
});

describe("claim tokens", () => {
  it("mints tokens the claim route will accept, and never the same one twice", () => {
    const tokens = new Set(Array.from({ length: 64 }, () => newClaimToken()));
    expect(tokens.size).toBe(64);
    for (const token of tokens) expect(claimTokenPattern.test(token)).toBe(true);
  });

  it("rejects anything that is not a minted token", () => {
    expect(claimTokenPattern.test("")).toBe(false);
    expect(claimTokenPattern.test("../../etc/passwd")).toBe(false);
    expect(claimTokenPattern.test(`${newClaimToken()}x`)).toBe(false);
  });

  it("stores a stable hash rather than the token itself", async () => {
    expect(await claimTokenHash("abc"))
      .toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const token = newClaimToken();
    const hash = await claimTokenHash(token);
    expect(hash).toBe(await claimTokenHash(token));
    expect(hash).not.toContain(token);
  });
});

describe("approval mail", () => {
  it("carries the claim link in both parts and nothing about the request", () => {
    const token = newClaimToken();
    const message = approvalEmail(token);
    const link = claimUrl(token);

    expect(link.startsWith(`${downloadsOrigin}/claim?t=`)).toBe(true);
    expect(message.text).toContain(link);
    expect(message.html).toContain(link);
    for (const part of [message.subject, message.text, message.html]) {
      expect(part).not.toContain("@");
    }
    expect(message.text.toLowerCase()).toContain("one-time pin");
    expect(message.text.toLowerCase()).toContain("github");
  });
});
