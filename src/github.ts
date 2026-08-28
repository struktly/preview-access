import { createPrivateKey, createSign } from "node:crypto";

function base64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

export async function signGitHubAppJwt(appId: string, privateKey: string, now = Date.now()): Promise<string> {
  // GitHub downloads PKCS#1 keys; createPrivateKey safely accepts both PKCS#1 and PKCS#8.
  const key = createPrivateKey(privateKey);
  const nowSeconds = Math.floor(now / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({ iat: nowSeconds - 60, exp: nowSeconds + 9 * 60, iss: appId }),
  );
  const unsigned = `${header}.${payload}`;
  const signature = createSign("RSA-SHA256").update(unsigned).end().sign(key).toString("base64url");
  return `${unsigned}.${signature}`;
}
