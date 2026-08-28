import { createVerify, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signGitHubAppJwt } from "../src/github.js";

describe("GitHub App authentication", () => {
  it("signs the PKCS#1 key format downloaded from GitHub", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { format: "pem", type: "pkcs1" },
      publicKeyEncoding: { format: "pem", type: "spki" },
    });
    const now = Date.parse("2026-08-28T12:00:00Z");
    const token = await signGitHubAppJwt("123456", privateKey, now);
    const [header, encodedPayload, signature] = token.split(".");
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));

    expect(payload.iat).toBe(Math.floor(now / 1000) - 60);
    expect(payload.exp).toBe(Math.floor(now / 1000) + 9 * 60);
    expect(payload.iss).toBe("123456");
    expect(
      createVerify("RSA-SHA256")
        .update(`${header}.${encodedPayload}`)
        .end()
        .verify(publicKey, Buffer.from(signature, "base64url")),
    ).toBe(true);
  });
});
