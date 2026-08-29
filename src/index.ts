import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  escapeHtml,
  githubLoginPattern,
  hasPreviewAccessOrigin,
  parseReleaseManifest,
} from "./core.js";

const downloadsHostname = "downloads.struktly.app";

type AccessRequest = {
  github_login: string;
  platform: "macos" | "linux" | "both";
  access_status: "pending";
  created_at: string;
};

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

async function sameSecret(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left.toLowerCase())),
    crypto.subtle.digest("SHA-256", encoder.encode(right.toLowerCase())),
  ]);
  return crypto.subtle.timingSafeEqual(leftHash, rightHash);
}

async function requireAccess(request: Request, env: Env, audience: string): Promise<string> {
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw new HttpError(403, "Access denied");

  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
  const jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  const { payload } = await jwtVerify(token, jwks, { audience, issuer });
  if (typeof payload.email !== "string" || payload.email.length === 0) {
    throw new HttpError(403, "Access denied");
  }
  return payload.email;
}

async function requireAdmin(request: Request, env: Env): Promise<void> {
  const email = await requireAccess(request, env, env.ACCESS_AUD);
  if (!(await sameSecret(email, env.ADMIN_EMAIL))) throw new HttpError(403, "Access denied");
}

async function requireApprovedDownloader(request: Request, env: Env): Promise<void> {
  const email = await requireAccess(request, env, env.DOWNLOADS_ACCESS_AUD);
  const result = await env.DB.prepare(
    `SELECT 1
     FROM access_requests
     WHERE email = ?1 COLLATE NOCASE
       AND access_status = 'active'
       AND platform IN ('macos', 'linux', 'both')
     LIMIT 1`,
  ).bind(email).first();
  if (!result) throw new HttpError(403, "Preview access is not active");
}

async function listRequests(env: Env): Promise<AccessRequest[]> {
  const result = await env.DB.prepare(
    `SELECT github_login, platform, access_status, created_at
     FROM access_requests
     WHERE github_login IS NOT NULL
       AND platform IN ('macos', 'linux', 'both')
       AND access_status = 'pending'
     ORDER BY created_at ASC`,
  ).all<AccessRequest>();
  return result.results;
}

async function activateRequest(env: Env, requestedLogin: string): Promise<void> {
  const login = requestedLogin.replace(/^@/, "");
  if (!githubLoginPattern.test(login)) throw new HttpError(400, "Invalid GitHub username");

  const result = await env.DB.prepare(
    `UPDATE access_requests
     SET access_status = 'active',
         approved_at = COALESCE(approved_at, CURRENT_TIMESTAMP),
         active_at = COALESCE(active_at, CURRENT_TIMESTAMP),
         revoked_at = NULL,
         updated_at = CURRENT_TIMESTAMP
     WHERE github_login = ?1 COLLATE NOCASE
       AND platform IN ('macos', 'linux', 'both')
       AND access_status = 'pending'`,
  ).bind(login).run();
  if (!result.success || result.meta.changes !== 1) throw new HttpError(404, "Pending request not found");
  console.log(JSON.stringify({ event: "preview_access_activated" }));
}

function adminPage(requests: AccessRequest[], message?: string): Response {
  const rows = requests.map((request) => {
    const login = escapeHtml(request.github_login);
    return `<li><div><strong>@${login}</strong><small>${escapeHtml(request.platform)}</small></div><form method="post" action="/approve"><input type="hidden" name="login" value="${login}"><button type="submit">Approve</button></form></li>`;
  }).join("");
  const content = rows || "<li class=empty>No requests need attention.</li>";
  const notice = message ? `<p class=notice>${escapeHtml(message)}</p>` : "";
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Preview access · Struktly</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:44rem;margin:4rem auto;padding:0 1.25rem}h1{font-size:1.75rem}p{color:#777}ul{list-style:none;padding:0;border-top:1px solid #8885}li{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1rem 0;border-bottom:1px solid #8885}small{display:block;color:#777}button{font:inherit;font-weight:650;padding:.55rem .9rem;border:0;border-radius:.45rem;background:#5b5cf0;color:white;cursor:pointer}.notice{padding:.8rem 1rem;border-radius:.45rem;background:#26834a22;color:inherit}.empty{color:#777}</style></head><body><main><h1>Preview access</h1><p>Approve download access to private release builds.</p>${notice}<ul>${content}</ul></main></body></html>`,
    { headers: secureHeaders("text/html; charset=utf-8") },
  );
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
    .map((asset) => `<li><strong>${escapeHtml(asset.name)}</strong><a href="/download/${encodeURIComponent(asset.id)}">Download</a></li>`)
    .join("");
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Preview downloads · Struktly</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:44rem;margin:4rem auto;padding:0 1.25rem}h1{font-size:1.75rem}p{color:#777}ul{list-style:none;padding:0;border-top:1px solid #8885}li{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1rem 0;border-bottom:1px solid #8885}a{font-weight:650}</style></head><body><main><h1>Preview downloads</h1><p>${escapeHtml(manifest.tag)}</p><ul>${assets}</ul></main></body></html>`,
    { headers: secureHeaders("text/html; charset=utf-8") },
  );
}

async function handleDownloads(request: Request, env: Env, url: URL): Promise<Response> {
  await requireApprovedDownloader(request, env);
  const manifest = await releaseManifest(env);
  if (request.method === "GET" && url.pathname === "/") return downloadsPage(manifest);

  const match = /^\/download\/([^/]+)$/.exec(url.pathname);
  if (request.method !== "GET" || !match) {
    return new Response("Not found", { status: 404, headers: secureHeaders("text/plain; charset=utf-8") });
  }
  const asset = manifest.assets.find((candidate) => candidate.id === decodeURIComponent(match[1]));
  if (!asset) return new Response("Not found", { status: 404, headers: secureHeaders("text/plain; charset=utf-8") });

  const object = await env.RELEASES.get(asset.key);
  if (!object) throw new Error("Published release asset is missing");
  const headers = new Headers(secureHeaders(object.httpMetadata?.contentType ?? "application/octet-stream"));
  headers.set("Content-Disposition", `attachment; filename="${asset.name}"`);
  headers.set("Content-Length", String(object.size));
  return new Response(object.body, { headers });
}

async function handleAdmin(request: Request, env: Env, url: URL): Promise<Response> {
  await requireAdmin(request, env);
  if (request.method === "GET" && url.pathname === "/") return adminPage(await listRequests(env));

  if (request.method === "POST" && url.pathname === "/approve") {
    if (!hasPreviewAccessOrigin(request)) throw new HttpError(403, "Invalid request origin");
    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.startsWith("application/x-www-form-urlencoded")) {
      throw new HttpError(415, "Unsupported request format");
    }
    const form = await request.formData();
    const login = form.get("login");
    if (typeof login !== "string") throw new HttpError(400, "GitHub username is required");
    await activateRequest(env, login);
    return adminPage(await listRequests(env), "Download access is active.");
  }

  return new Response("Not found", { status: 404, headers: secureHeaders("text/plain; charset=utf-8") });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      return url.hostname === downloadsHostname
        ? await handleDownloads(request, env, url)
        : await handleAdmin(request, env, url);
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
