import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe("access boundary", () => {
  it("denies requests without a Cloudflare Access token", async () => {
    const request = new IncomingRequest("https://preview-access.struktly.io/");
    const response = await worker.fetch(request, env);

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("Access denied");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
