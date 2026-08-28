import { describe, expect, it } from "vitest";
import { escapeHtml, githubLoginPattern, parseRepository } from "../src/core";

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
});
