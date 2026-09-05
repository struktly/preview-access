import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  activateRequestStatement,
  activeDownloaderQuery,
  approvalEmail,
  claimTokenHash,
  claimTokenPattern,
  declineRequestStatement,
  downloadsOrigin,
  escapeHtml,
  githubLoginPattern,
  hasPreviewAccessOrigin,
  newClaimToken,
  parseReleaseManifest,
  recordDownloadStatement,
  redeemClaimStatement,
  revokeAccessStatement,
} from "./core.js";

const downloadsHostname = new URL(downloadsOrigin).hostname;

type AccessRequest = {
  github_login: string;
  platform: "macos" | "linux" | "both";
  access_status: "pending" | "active" | "declined" | "revoked";
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

async function requireApprovedDownloader(request: Request, env: Env): Promise<string> {
  const email = await requireAccess(request, env, env.DOWNLOADS_ACCESS_AUD);
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

async function listRequests(env: Env): Promise<AccessRequest[]> {
  const result = await env.DB.prepare(
    `SELECT github_login, platform, access_status, created_at
     FROM access_requests
     WHERE github_login IS NOT NULL
       AND platform IN ('macos', 'linux', 'both')
     ORDER BY CASE access_status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END,
              created_at ASC`,
  ).all<AccessRequest>();
  return result.results;
}

function validLogin(requestedLogin: string): string {
  const login = requestedLogin.replace(/^@/, "");
  if (!githubLoginPattern.test(login)) throw new HttpError(400, "Invalid GitHub username");
  return login;
}

async function declineRequest(env: Env, requestedLogin: string): Promise<void> {
  const declined = await env.DB.prepare(declineRequestStatement).bind(validLogin(requestedLogin)).first();
  if (!declined) throw new HttpError(404, "Pending request not found");
  console.log(JSON.stringify({ event: "preview_access_declined" }));
}

async function revokeAccess(env: Env, requestedLogin: string): Promise<void> {
  const revoked = await env.DB.prepare(revokeAccessStatement).bind(validLogin(requestedLogin)).first();
  if (!revoked) throw new HttpError(404, "Active access not found");
  console.log(JSON.stringify({ event: "preview_access_revoked" }));
}

/** Activates the request and returns the address to notify with its claim token. */
async function activateRequest(env: Env, requestedLogin: string): Promise<{ email: string; token: string }> {
  const token = newClaimToken();
  const activated = await env.DB.prepare(activateRequestStatement)
    .bind(validLogin(requestedLogin), await claimTokenHash(token))
    .first<{ email: string }>();
  if (!activated) throw new HttpError(404, "Pending request not found");
  console.log(JSON.stringify({ event: "preview_access_activated" }));
  return { email: activated.email, token };
}

/** The row is already committed, so a bounce must never undo an approval. */
async function sendApproval(env: Env, email: string, token: string): Promise<boolean> {
  const message = approvalEmail(token);
  try {
    await env.EMAIL.send({
      to: email,
      from: { email: env.NOTIFICATION_FROM, name: "Struktly" },
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
    console.log(JSON.stringify({ event: "preview_access_email_sent" }));
    return true;
  } catch {
    console.error(JSON.stringify({ event: "preview_access_email_failed" }));
    return false;
  }
}

/** Binds the signed-in Access identity to an approval, whichever provider it came from. */
async function claimAccess(request: Request, env: Env, url: URL): Promise<Response> {
  const email = await requireAccess(request, env, env.DOWNLOADS_ACCESS_AUD);
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

function actionForm(action: string, login: string, label: string, secondary = false): string {
  const kind = secondary ? ' class=secondary' : "";
  return `<form method="post" action="/${action}"><input type="hidden" name="login" value="${login}"><button type="submit"${kind}>${label}</button></form>`;
}

function adminPage(requests: AccessRequest[], message?: string): Response {
  const rows = requests.map((request) => {
    const login = escapeHtml(request.github_login);
    // A declined or removed row keeps Approve: history is visible, and a
    // decision can be reversed from here rather than by editing D1.
    const actions = request.access_status === "pending"
      ? actionForm("approve", login, "Approve") + actionForm("decline", login, "Decline", true)
      : request.access_status === "active"
        ? actionForm("revoke", login, "Remove", true)
        : actionForm("approve", login, "Approve", true);
    const since = escapeHtml(request.created_at.slice(0, 10));
    return `<li><div><strong>@${login}</strong><small>${escapeHtml(request.platform)} · ${request.access_status} · requested ${since}</small></div><div class=actions>${actions}</div></li>`;
  }).join("");
  const content = rows || "<li class=empty>No requests yet.</li>";
  const notice = message ? `<p class=notice>${escapeHtml(message)}</p>` : "";
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Preview access · Struktly</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:44rem;margin:4rem auto;padding:0 1.25rem}h1{font-size:1.75rem}p{color:#777}ul{list-style:none;padding:0;border-top:1px solid #8885}li{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1rem 0;border-bottom:1px solid #8885}small{display:block;color:#777}.actions{display:flex;gap:.5rem}button{font:inherit;font-weight:650;padding:.55rem .9rem;border:0;border-radius:.45rem;background:#5b5cf0;color:white;cursor:pointer}.secondary{background:#8884;color:inherit}.notice{padding:.8rem 1rem;border-radius:.45rem;background:#26834a22;color:inherit}.empty{color:#777}</style></head><body><main><h1>Preview access</h1><p>Approve, decline, or remove download access to private release builds.</p>${notice}<ul>${content}</ul></main></body></html>`,
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

async function handleDownloads(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  if (request.method === "GET" && url.pathname === "/claim") return claimAccess(request, env, url);

  const identity = await requireApprovedDownloader(request, env);
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
  ctx.waitUntil(recordDownload(env, identity, manifest.tag, asset.id));
  const headers = new Headers(secureHeaders(object.httpMetadata?.contentType ?? "application/octet-stream"));
  headers.set("Content-Disposition", `attachment; filename="${asset.name}"`);
  headers.set("Content-Length", String(object.size));
  return new Response(object.body, { headers });
}

async function handleAdmin(request: Request, env: Env, url: URL): Promise<Response> {
  await requireAdmin(request, env);
  if (request.method === "GET" && url.pathname === "/") return adminPage(await listRequests(env));

  if (request.method !== "POST" || !["/approve", "/decline", "/revoke"].includes(url.pathname)) {
    return new Response("Not found", { status: 404, headers: secureHeaders("text/plain; charset=utf-8") });
  }

  if (!hasPreviewAccessOrigin(request)) throw new HttpError(403, "Invalid request origin");
  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.startsWith("application/x-www-form-urlencoded")) {
    throw new HttpError(415, "Unsupported request format");
  }
  const form = await request.formData();
  const login = form.get("login");
  if (typeof login !== "string") throw new HttpError(400, "GitHub username is required");

  if (url.pathname === "/decline") {
    await declineRequest(env, login);
    return adminPage(await listRequests(env), "The request is declined.");
  }
  if (url.pathname === "/revoke") {
    await revokeAccess(env, login);
    return adminPage(await listRequests(env), "Download access is removed.");
  }

  const activated = await activateRequest(env, login);
  const notified = await sendApproval(env, activated.email, activated.token);
  return adminPage(
    await listRequests(env),
    notified
      ? "Download access is active and the approval email is on its way."
      : "Download access is active, but the approval email could not be sent.",
  );
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);
      return url.hostname === downloadsHostname
        ? await handleDownloads(request, env, ctx, url)
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
