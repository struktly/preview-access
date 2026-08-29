import { describe, expect, it } from "vitest";
import {
  escapeHtml,
  githubLoginPattern,
  hasPreviewAccessOrigin,
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
