export const githubLoginPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
export const previewAccessOrigin = "https://preview-access.struktly.app";
const releaseTagPattern = /^v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/;
const releaseAssetIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const releaseAssetNamePattern = /^[A-Za-z0-9][A-Za-z0-9._ -]{0,255}$/;
const releaseAssetKeyPattern = /^releases\/v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\/[A-Za-z0-9][A-Za-z0-9._ -]{0,255}$/;

export type ReleaseAsset = { id: string; key: string; name: string };
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

export function parseReleaseManifest(value: unknown): ReleaseManifest {
  if (!value || typeof value !== "object") throw new Error("Invalid release manifest");
  const manifest = value as Partial<ReleaseManifest>;
  if (manifest.version !== 1 || typeof manifest.tag !== "string" || !releaseTagPattern.test(manifest.tag)) {
    throw new Error("Invalid release manifest");
  }
  if (!Array.isArray(manifest.assets) || manifest.assets.length === 0) {
    throw new Error("Invalid release manifest");
  }
  const assets = manifest.assets.map((asset) => {
    if (!asset || typeof asset !== "object") throw new Error("Invalid release manifest");
    const candidate = asset as Partial<ReleaseAsset>;
    if (
      typeof candidate.id !== "string" || !releaseAssetIdPattern.test(candidate.id) ||
      typeof candidate.name !== "string" || !releaseAssetNamePattern.test(candidate.name) ||
      typeof candidate.key !== "string" || !releaseAssetKeyPattern.test(candidate.key) ||
      candidate.key !== `releases/${manifest.tag}/${candidate.name}`
    ) {
      throw new Error("Invalid release manifest");
    }
    return { id: candidate.id, key: candidate.key, name: candidate.name };
  });
  if (new Set(assets.map((asset) => asset.id)).size !== assets.length) {
    throw new Error("Invalid release manifest");
  }
  return { version: 1, tag: manifest.tag, assets };
}
