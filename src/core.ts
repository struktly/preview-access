export const githubLoginPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
export const previewAccessOrigin = "https://preview-access.struktly.app";
export const downloadsOrigin = "https://downloads.struktly.app";
// 32 random bytes, base64url without padding.
export const claimTokenPattern = /^[A-Za-z0-9_-]{43}$/;
const releaseTagPattern = /^v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/;
const releaseAssetIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const releaseAssetNamePattern = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,255}$/;
const releaseAssetKeyPattern = /^releases\/v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\/[A-Za-z0-9][A-Za-z0-9._ -]{0,255}$/;
// Escaped before it renders; this only keeps control characters out of the page.
const releaseAssetLabelPattern = /^[^\u0000-\u001f\u007f]{1,64}$/;

// `label` is optional so a manifest published before labelling still parses.
export type ReleaseAsset = { id: string; key: string; name: string; label?: string };
export type ReleaseManifest = { version: 1; tag: string; assets: ReleaseAsset[] };

export function hasPreviewAccessOrigin(request: Request): boolean {
  if (request.headers.get("origin") === previewAccessOrigin) return true;
  if (
    request.headers.get("origin") === "null" &&
    request.headers.get("sec-fetch-site") === "same-origin" &&
    request.headers.get("sec-fetch-mode") === "navigate" &&
    request.headers.get("sec-fetch-dest") === "document" &&
    request.headers.get("sec-fetch-user") === "?1"
  ) {
    return true;
  }
  try {
    return new URL(request.headers.get("referer") ?? "").origin === previewAccessOrigin;
  } catch {
    return false;
  }
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const escaped: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return escaped[character];
  });
}

/** Why this row cannot be offered, or null when it can. */
function assetFault(value: unknown, tag: string, seen: Set<string>): string | null {
  if (!value || typeof value !== "object") return "not an object";
  const asset = value as Partial<ReleaseAsset>;
  if (typeof asset.id !== "string" || !releaseAssetIdPattern.test(asset.id)) return "unusable id";
  if (typeof asset.name !== "string" || !releaseAssetNamePattern.test(asset.name)) {
    return `unusable name for ${asset.id}`;
  }
  if (
    typeof asset.key !== "string" || !releaseAssetKeyPattern.test(asset.key) ||
    asset.key !== `releases/${tag}/${asset.name}`
  ) {
    return `key does not address this release for ${asset.id}`;
  }
  if (asset.label !== undefined &&
      (typeof asset.label !== "string" || !releaseAssetLabelPattern.test(asset.label))) {
    return `unusable label for ${asset.id}`;
  }
  if (seen.has(asset.id)) return `duplicate id ${asset.id}`;
  return null;
}

/**
 * One unpublishable row must not close the download page on every approved
 * tester, so a bad asset is dropped and reported to the log. A manifest whose
 * rows are all unusable is still invalid — there is nothing to offer.
 */
export function parseReleaseManifest(value: unknown): ReleaseManifest {
  if (!value || typeof value !== "object") throw new Error("Invalid release manifest");
  const manifest = value as Partial<ReleaseManifest>;
  if (manifest.version !== 1 || typeof manifest.tag !== "string" || !releaseTagPattern.test(manifest.tag)) {
    throw new Error("Invalid release manifest");
  }
  if (!Array.isArray(manifest.assets) || manifest.assets.length === 0) {
    throw new Error("Invalid release manifest");
  }
  const tag = manifest.tag;
  const seen = new Set<string>();
  const assets: ReleaseAsset[] = [];
  for (const candidate of manifest.assets) {
    const fault = assetFault(candidate, tag, seen);
    if (fault !== null) {
      console.warn(`Release manifest ${tag}: skipped an asset (${fault})`);
      continue;
    }
    const asset = candidate as ReleaseAsset;
    seen.add(asset.id);
    assets.push({ id: asset.id, key: asset.key, name: asset.name, ...(asset.label ? { label: asset.label } : {}) });
  }
  if (assets.length === 0) throw new Error("Invalid release manifest");
  return { version: 1, tag, assets };
}

export function newClaimToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Only the hash reaches D1, so a leaked row cannot be replayed as a claim. */
export async function claimTokenHash(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function claimUrl(token: string): string {
  return `${downloadsOrigin}/claim?t=${encodeURIComponent(token)}`;
}

/** The one transactional mail this service sends. Carries no request detail. */
export function approvalEmail(token: string): { subject: string; text: string; html: string } {
  const link = claimUrl(token);
  return {
    subject: "Your Struktly preview access is approved",
    text: [
      "Your request for Struktly preview access is approved.",
      "",
      `Open this link to verify yourself and reach the builds:`,
      link,
      "",
      "Cloudflare Access will ask you to sign in first. Use a one-time PIN sent",
      "to this address, or sign in with GitHub -- either proves who you are, and",
      "the link binds that sign-in to your approval.",
      "",
      "The link works once and expires in 14 days. After that, downloads stay at",
      downloadsOrigin,
      "",
      "-- Struktly",
    ].join("\n"),
    html: [
      '<!doctype html><html lang="en"><body style="font:16px/1.6 system-ui,sans-serif;color:#111;max-width:34rem;margin:0 auto;padding:1.5rem">',
      "<p>Your request for Struktly preview access is approved.</p>",
      `<p><a href="${escapeHtml(link)}" style="font-weight:650">Verify yourself and open the preview builds</a></p>`,
      "<p>Cloudflare Access will ask you to sign in first. Use a one-time PIN sent to this address, or sign in with GitHub &mdash; either proves who you are, and the link binds that sign-in to your approval.</p>",
      `<p>The link works once and expires in 14 days. After that, downloads stay at <a href="${downloadsOrigin}">${downloadsOrigin}</a>.</p>`,
      "<p>&mdash; Struktly</p>",
      "</body></html>",
    ].join(""),
  };
}

// The statements the download gate turns on, kept here so the D1 test drives the
// exact text the Worker runs rather than a copy of it. `datetime('now', ...)`
// writes the expiry in the format CURRENT_TIMESTAMP compares against.
export const activeDownloaderQuery = `SELECT 1
   FROM access_requests
   WHERE (email = ?1 COLLATE NOCASE OR claimed_email = ?1 COLLATE NOCASE)
     AND access_status = 'active'
     AND platform IN ('macos', 'linux', 'both')
   LIMIT 1`;

export const activateRequestStatement = `UPDATE access_requests
   SET access_status = 'active',
       approved_at = COALESCE(approved_at, CURRENT_TIMESTAMP),
       active_at = COALESCE(active_at, CURRENT_TIMESTAMP),
       revoked_at = NULL,
       claim_token_hash = ?2,
       claim_expires_at = datetime('now', '+14 days'),
       claimed_email = NULL,
       claimed_at = NULL,
       updated_at = CURRENT_TIMESTAMP
   WHERE github_login = ?1 COLLATE NOCASE
     AND platform IN ('macos', 'linux', 'both')
     AND access_status = 'pending'
   RETURNING email`;

export const redeemClaimStatement = `UPDATE access_requests
   SET claimed_email = ?2,
       claimed_at = CURRENT_TIMESTAMP,
       claim_token_hash = NULL,
       claim_expires_at = NULL,
       updated_at = CURRENT_TIMESTAMP
   WHERE claim_token_hash = ?1
     AND access_status = 'active'
     AND claim_expires_at > CURRENT_TIMESTAMP
   RETURNING 1 AS claimed`;
