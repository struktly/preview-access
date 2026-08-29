import { describe, expect, it } from "vitest";
import {
  escapeHtml,
  githubLoginPattern,
  hasPreviewAccessOrigin,
  parseRepository,
  previewAccessOrigin,
} from "../src/core.js";

describe("public input boundaries", () => {
  it("accepts valid GitHub usernames and rejects malformed ones", () => {
    expect(githubLoginPattern.test("n1dre")).toBe(true);
    expect(githubLoginPattern.test("valid-user")).toBe(true);
    expect(githubLoginPattern.test("-invalid")).toBe(false);
    expect(githubLoginPattern.test("invalid/user")).toBe(false);
  });

  it("requires an owner/repository pair", () => {
    expect(parseRepository("struktly/releases")).toEqual({ owner: "struktly", repo: "releases" });
    expect(() => parseRepository("releases")).toThrow("Invalid release repository configuration");
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
