import { createRemoteJWKSet, jwtVerify } from "jose";
import { escapeHtml, githubLoginPattern, hasPreviewAccessOrigin, parseRepository } from "./core.js";
import { signGitHubAppJwt } from "./github.js";

const githubApiVersion = "2026-03-10";

type AccessRequest = {
  github_login: string;
  platform: "macos" | "linux" | "both";
  access_status: "pending" | "invited";
  created_at: string;
};

type Installation = { id: number };
type InstallationToken = { token: string };

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
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

async function requireAdmin(request: Request, env: Env): Promise<void> {
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw new HttpError(403, "Access denied");

  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
  const jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  const { payload } = await jwtVerify(token, jwks, {
    audience: env.ACCESS_AUD,
    issuer,
  });
  if (typeof payload.email !== "string" || !(await sameSecret(payload.email, env.ADMIN_EMAIL))) {
    throw new HttpError(403, "Access denied");
  }
}

async function listRequests(env: Env): Promise<AccessRequest[]> {
  const result = await env.DB.prepare(
    `SELECT github_login, platform, access_status, created_at
     FROM access_requests
     WHERE github_login IS NOT NULL
       AND platform IN ('macos', 'linux', 'both')
       AND access_status IN ('pending', 'invited')
     ORDER BY created_at ASC`,
  ).all<AccessRequest>();
  return result.results;
}

async function findRequest(env: Env, login: string): Promise<AccessRequest | null> {
  return env.DB.prepare(
    `SELECT github_login, platform, access_status, created_at
     FROM access_requests
     WHERE github_login = ?1 COLLATE NOCASE
       AND platform IN ('macos', 'linux', 'both')
       AND access_status IN ('pending', 'invited')`,
  )
    .bind(login)
    .first<AccessRequest>();
}

async function githubAppJwt(env: Env): Promise<string> {
  return signGitHubAppJwt(env.GITHUB_APP_ID, env.GITHUB_APP_PRIVATE_KEY);
}

async function githubRequest(
  path: string,
  token: string,
  init: RequestInit = {},
): Promise<Response> {
  const response = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "struktly-preview-access",
      "X-GitHub-Api-Version": githubApiVersion,
      ...init.headers,
    },
  });
  return response;
}

async function readBoundedJson<T>(response: Response): Promise<T> {
  const length = Number(response.headers.get("content-length") ?? "0");
  if (length > 256_000) throw new Error("Unexpectedly large GitHub response");
  return response.json<T>();
}

async function installationToken(env: Env, owner: string, repo: string): Promise<string> {
  const appJwt = await githubAppJwt(env);
  const installationResponse = await githubRequest(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/installation`,
    appJwt,
  );
  if (!installationResponse.ok) throw new Error("GitHub App installation lookup failed");
  const installation = await readBoundedJson<Installation>(installationResponse);
  if (!Number.isSafeInteger(installation.id)) throw new Error("Invalid GitHub App installation response");

  const tokenResponse = await githubRequest(
    `/app/installations/${installation.id}/access_tokens`,
    appJwt,
    {
      method: "POST",
      body: JSON.stringify({
        repositories: [repo],
        permissions: { administration: "write" },
      }),
    },
  );
  if (!tokenResponse.ok) throw new Error("GitHub App token creation failed");
  const result = await readBoundedJson<InstallationToken>(tokenResponse);
  if (typeof result.token !== "string" || result.token.length === 0) {
    throw new Error("Invalid GitHub App token response");
  }
  return result.token;
}

async function isCollaborator(owner: string, repo: string, login: string, token: string): Promise<boolean> {
  const response = await githubRequest(
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/collaborators/${encodeURIComponent(login)}`,
    token,
  );
  if (response.status === 204) return true;
  if (response.status === 404) return false;
  throw new Error("GitHub collaborator check failed");
}

async function updateStatus(env: Env, login: string, status: "invited" | "active"): Promise<void> {
  const timestampColumn = status === "active" ? "active_at" : "invited_at";
  const result = await env.DB.prepare(
    `UPDATE access_requests
     SET access_status = ?2,
         approved_at = COALESCE(approved_at, CURRENT_TIMESTAMP),
         invited_at = COALESCE(invited_at, CURRENT_TIMESTAMP),
         ${timestampColumn} = COALESCE(${timestampColumn}, CURRENT_TIMESTAMP),
         revoked_at = NULL,
         updated_at = CURRENT_TIMESTAMP
     WHERE github_login = ?1 COLLATE NOCASE
       AND platform IN ('macos', 'linux', 'both')
       AND access_status IN ('pending', 'invited')`,
  )
    .bind(login, status)
    .run();
  if (!result.success || result.meta.changes !== 1) throw new Error("Access status update failed");
}

async function approve(env: Env, requestedLogin: string): Promise<"invited" | "active"> {
  const login = requestedLogin.replace(/^@/, "");
  if (!githubLoginPattern.test(login)) throw new HttpError(400, "Invalid GitHub username");

  const request = await findRequest(env, login);
  if (!request) throw new HttpError(404, "Pending request not found");

  const { owner, repo } = parseRepository(env.RELEASES_REPO);
  const token = await installationToken(env, owner, repo);
  let active = await isCollaborator(owner, repo, request.github_login, token);
  if (!active) {
    const inviteResponse = await githubRequest(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/collaborators/${encodeURIComponent(request.github_login)}`,
      token,
      { method: "PUT", body: JSON.stringify({ permission: "pull" }) },
    );
    if (inviteResponse.status !== 201 && inviteResponse.status !== 204) {
      throw new Error("GitHub invitation failed");
    }
    active = await isCollaborator(owner, repo, request.github_login, token);
  }

  const status = active ? "active" : "invited";
  await updateStatus(env, request.github_login, status);
  console.log(JSON.stringify({ event: "preview_access_updated", status }));
  return status;
}

function page(requests: AccessRequest[], message?: string): Response {
  const rows = requests
    .map((request) => {
      const login = escapeHtml(request.github_login);
      const action = request.access_status === "pending" ? "Approve" : "Check access";
      return `<li><div><strong>@${login}</strong><small>${escapeHtml(request.platform)} · ${escapeHtml(request.access_status)}</small></div><form method="post" action="/approve"><input type="hidden" name="login" value="${login}"><button type="submit">${action}</button></form></li>`;
    })
    .join("");
  const content = rows || "<li class=empty>No requests need attention.</li>";
  const notice = message ? `<p class=notice>${escapeHtml(message)}</p>` : "";
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Preview access · Struktly</title><style>:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{max-width:44rem;margin:4rem auto;padding:0 1.25rem}h1{font-size:1.75rem}p{color:#777}ul{list-style:none;padding:0;border-top:1px solid #8885}li{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1rem 0;border-bottom:1px solid #8885}small{display:block;color:#777}button{font:inherit;font-weight:650;padding:.55rem .9rem;border:0;border-radius:.45rem;background:#5b5cf0;color:white;cursor:pointer}.notice{padding:.8rem 1rem;border-radius:.45rem;background:#26834a22;color:inherit}.empty{color:#777}</style></head><body><main><h1>Preview access</h1><p>Approve read-only access to private release builds.</p>${notice}<ul>${content}</ul></main></body></html>`,
    { headers: secureHeaders("text/html; charset=utf-8") },
  );
}

async function handle(request: Request, env: Env): Promise<Response> {
  await requireAdmin(request, env);
  const url = new URL(request.url);
  if (request.method === "GET" && url.pathname === "/") return page(await listRequests(env));

  if (request.method === "POST" && url.pathname === "/approve") {
    if (!hasPreviewAccessOrigin(request)) throw new HttpError(403, "Invalid request origin");
    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.startsWith("application/x-www-form-urlencoded")) {
      throw new HttpError(415, "Unsupported request format");
    }
    const form = await request.formData();
    const login = form.get("login");
    if (typeof login !== "string") throw new HttpError(400, "GitHub username is required");
    const status = await approve(env, login);
    const message = status === "active" ? "Access is active." : "Invitation sent. The tester must accept it on GitHub.";
    return page(await listRequests(env), message);
  }

  return new Response("Not found", { status: 404, headers: secureHeaders("text/plain; charset=utf-8") });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handle(request, env);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      if (status === 500) console.error(JSON.stringify({ event: "preview_access_error" }));
      const message = error instanceof HttpError ? error.message : "Internal server error";
      return new Response(message, { status, headers: secureHeaders("text/plain; charset=utf-8") });
    }
  },
} satisfies ExportedHandler<Env>;
