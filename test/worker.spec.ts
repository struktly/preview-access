import { createExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index.js";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe("access boundary", () => {
  it("answers only on the download hostname", async () => {
    const request = new IncomingRequest("https://preview-access.struktly.app/");
    const response = await worker.fetch(request, env, createExecutionContext());

    expect(response.status).toBe(404);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("requires an Access token at the download hostname", async () => {
    const request = new IncomingRequest("https://downloads.struktly.app/");
    const response = await worker.fetch(request, env, createExecutionContext());

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("Access denied");
  });

  it("will not let a claim link stand in for signing in", async () => {
    const request = new IncomingRequest(
      "https://downloads.struktly.app/claim?t=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    const response = await worker.fetch(request, env, createExecutionContext());

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("Access denied");
  });
});
