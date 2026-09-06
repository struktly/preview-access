import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  activeDownloaderQuery,
  claimTokenHash,
  claimTokenPattern,
  downloadsOrigin,
  escapeHtml,
  parseReleaseManifest,
  recordDownloadStatement,
  redeemClaimStatement,
} from "./core.js";

const downloadsHostname = new URL(downloadsOrigin).hostname;

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function secureHeaders(contentType: string): HeadersInit {
  return {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "Content-Type": contentType,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
}

async function requireAccess(request: Request, env: Env): Promise<string> {
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw new HttpError(403, "Access denied");

  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
  const jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  const { payload } = await jwtVerify(token, jwks, { audience: env.DOWNLOADS_ACCESS_AUD, issuer });
  if (typeof payload.email !== "string" || payload.email.length === 0) {
    throw new HttpError(403, "Access denied");
  }
  return payload.email;
}

async function requireApprovedDownloader(request: Request, env: Env): Promise<string> {
  const email = await requireAccess(request, env);
  const result = await env.DB.prepare(activeDownloaderQuery).bind(email).first();
  if (!result) throw new HttpError(403, "Preview access is not active");
  return email;
}

/** The asset is already streaming; a failed record must not turn it into an error. */
async function recordDownload(env: Env, identity: string, releaseTag: string, assetId: string): Promise<void> {
  try {
    await env.DB.prepare(recordDownloadStatement).bind(identity, releaseTag, assetId).run();
  } catch {
    console.error(JSON.stringify({ event: "preview_download_unrecorded" }));
  }
}

/** Binds the signed-in Access identity to an approval, whichever provider it came from. */
async function claimAccess(request: Request, env: Env, url: URL): Promise<Response> {
  const email = await requireAccess(request, env);
  const token = url.searchParams.get("t") ?? "";
  if (!claimTokenPattern.test(token)) throw new HttpError(400, "This verification link is not valid");

  const claimed = await env.DB.prepare(redeemClaimStatement)
    .bind(await claimTokenHash(token), email)
    .first();
  if (!claimed) throw new HttpError(403, "This verification link has expired or was already used");

  console.log(JSON.stringify({ event: "preview_access_claimed" }));
  return new Response(null, {
    status: 303,
    headers: { ...secureHeaders("text/plain; charset=utf-8"), Location: `${downloadsOrigin}/` },
  });
}

async function releaseManifest(env: Env) {
  const object = await env.RELEASES.get("latest.json");
  if (!object) throw new HttpError(503, "No preview release is available");
  if (object.size > 128_000) throw new Error("Release manifest is unexpectedly large");
  try {
    return parseReleaseManifest(JSON.parse(await object.text()));
  } catch {
    throw new Error("Release manifest is invalid");
  }
}

function downloadsPage(manifest: Awaited<ReturnType<typeof releaseManifest>>): Response {
  const assets = manifest.assets
    .map((asset) => {
      const heading = escapeHtml(asset.label ?? asset.name);
      const detail = asset.label ? `<small>${escapeHtml(asset.name)}</small>` : "";
      return `<li><div><strong>${heading}</strong>${detail}</div><a href="/download/${encodeURIComponent(asset.id)}">Download</a></li>`;
    })
    .join("");
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Preview downloads · Struktly</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:44rem;margin:4rem auto;padding:0 1.25rem}h1{font-size:1.75rem}p{color:#777}ul{list-style:none;padding:0;border-top:1px solid #8885}li{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1rem 0;border-bottom:1px solid #8885}small{display:block;color:#777}a{font-weight:650}</style></head><body><main><h1>Preview downloads</h1><p>${escapeHtml(manifest.tag)}</p><ul>${assets}</ul></main></body></html>`,
    { headers: secureHeaders("text/html; charset=utf-8") },
  );
}

function notFound(): Response {
  return new Response("Not found", { status: 404, headers: secureHeaders("text/plain; charset=utf-8") });
}

async function handleDownloads(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  if (request.method === "GET" && url.pathname === "/claim") return claimAccess(request, env, url);

  const identity = await requireApprovedDownloader(request, env);
  const manifest = await releaseManifest(env);
  if (request.method === "GET" && url.pathname === "/") return downloadsPage(manifest);

  const match = /^\/download\/([^/]+)$/.exec(url.pathname);
  if (request.method !== "GET" || !match) return notFound();
  const asset = manifest.assets.find((candidate) => candidate.id === decodeURIComponent(match[1]));
  if (!asset) return notFound();

  const object = await env.RELEASES.get(asset.key);
  if (!object) throw new Error("Published release asset is missing");
  ctx.waitUntil(recordDownload(env, identity, manifest.tag, asset.id));
  const headers = new Headers(secureHeaders(object.httpMetadata?.contentType ?? "application/octet-stream"));
  headers.set("Content-Disposition", `attachment; filename="${asset.name}"`);
  headers.set("Content-Length", String(object.size));
  return new Response(object.body, { headers });
}

// The founder's side -- approving, declining, removing, and the approval mail --
// lives in the private admin Worker. This one answers only on the download
// hostname, and only to a signed-in identity.
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.hostname !== downloadsHostname) return notFound();
      return await handleDownloads(request, env, ctx, url);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      if (status === 500) {
        const reason = error instanceof Error ? error.message : "Unknown error";
        console.error(JSON.stringify({ event: "preview_access_error", reason }));
      }
      const message = error instanceof HttpError ? error.message : "Internal server error";
      return new Response(message, { status, headers: secureHeaders("text/plain; charset=utf-8") });
    }
  },
} satisfies ExportedHandler<Env>;
