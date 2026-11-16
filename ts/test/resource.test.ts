import { describe, expect, it } from "vitest";
import { createGatekeeper, NotServedError, type Req } from "../src/index.js";

// FR-Z12 (ADR-0108): resource checks go to the server every time.
function server() {
  let calls = 0;
  const decide = (r: string) => r === "campaign:1" ? { allow: true, matched_by: "relation:can_edit" }
    : r === "campaign:2" ? { allow: false, matched_by: "step_up_required", max_age: 300 } : { allow: false, matched_by: "none" };
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    calls++;
    if (new Headers(init?.headers).get("authorization") !== "Bearer tok") return new Response("", { status: 401 });
    const url = String(input);
    const body = JSON.parse(String(init?.body));
    if (url.endsWith("/v1/authz/check")) return Response.json(decide(body.resource));
    if (url.endsWith("/v1/authz/check-batch")) return Response.json({ results: body.checks.map((c: { resource: string }) => decide(c.resource)) });
    return new Response("", { status: 404 });
  }) as typeof fetch;
  return { f, calls: () => calls };
}

describe("resource checks", () => {
  it("asks every time and batches", async () => {
    const s = server();
    const g = createGatekeeper({ issuer: "https://auth.test/t/acme", audience: "api", clientId: "api", fetch: s.f });
    expect(await g.canOn("tok", "campaign:update", "campaign:1")).toEqual({ allow: true, matched_by: "relation:can_edit" });
    await g.canOn("tok", "campaign:update", "campaign:1");
    expect(s.calls()).toBe(2);
    const each = await g.canOnEach("tok", "campaign:update", ["campaign:1", "campaign:3", "campaign:2"]);
    expect(each.map((d) => d.allow)).toEqual([true, false, false]);
    expect(each[2].max_age).toBe(300);
    await expect(g.canOn("wrong", "campaign:update", "campaign:1")).rejects.toThrow(/unavailable/);
  });

  it("guards a route", async () => {
    const g = createGatekeeper({ issuer: "https://auth.test/t/acme", audience: "api", clientId: "api", fetch: server().f });
    const guard = g.requirePermissionOn("campaign:update", (req) => String((req as Req & { params: { id: string } }).params.id));
    const run = (id: string, auth: string, verified = true) => new Promise<{ status: number; header?: string }>((resolve) => {
      const req = { headers: { authorization: auth }, params: { id }, ...(verified ? { gatekeeper: {} } : {}) } as unknown as Req;
      let status = 0, header: string | undefined;
      const res = { status: (c: number) => { status = c; return res; }, setHeader: (_: string, v: string) => { header = v; return res; },
        end: () => { resolve({ status, header }); return res; } };
      guard(req, res, () => resolve({ status: 200 }));
    });
    expect((await run("campaign:1", "Bearer tok")).status).toBe(200);
    expect((await run("campaign:3", "Bearer tok")).status).toBe(403);
    const step = await run("campaign:2", "Bearer tok");
    expect(step).toEqual({ status: 401, header: 'Bearer error="insufficient_user_authentication", max_age="300", acr_values="mfa"' });
    expect((await run("campaign:1", "DPoP tok")).status).toBe(403);
    expect((await run("campaign:1", "Bearer tok", false)).status).toBe(403);
    expect((await run("campaign:1", "Bearer other")).status).toBe(503);
  });
});

// FR-Z16 (ADR-0119): checks for a user with the client's own credentials.
function onBehalfServer() {
  let tokens = 0;
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const auth = new Headers(init?.headers).get("authorization") ?? "";
    if (url.endsWith("/oauth2/token")) {
      tokens++;
      const form = new URLSearchParams(String(init?.body));
      if (auth !== "Basic " + Buffer.from("shop:s3cret").toString("base64") || form.get("scope") !== "authz:check") return new Response("", { status: 401 });
      return Response.json({ access_token: "cc", expires_in: 300 });
    }
    if (auth !== "Bearer cc") return new Response("", { status: 401 });
    const body = JSON.parse(String(init?.body));
    if (body.user_id !== "u-1") return Response.json({ type: "https://gatekeeper.dev/problems/user-not-served" }, { status: 403 });
    if (url.endsWith("/v1/authz/check")) return Response.json({ allow: body.resource === "campaign:1", matched_by: "relation:can_edit" });
    if (url.endsWith("/v1/authz/check-batch")) return Response.json({ results: body.checks.map((c: { resource: string }) => ({ allow: c.resource === "campaign:1", matched_by: "none" })) });
    return new Response("", { status: 404 });
  }) as typeof fetch;
  return { f, tokens: () => tokens };
}

describe("checks on behalf", () => {
  it("uses and caches the client's token", async () => {
    const s = onBehalfServer();
    const g = createGatekeeper({ issuer: "https://auth.test/t/acme", audience: "api", clientId: "shop", clientSecret: "s3cret", fetch: s.f });
    expect((await g.canOnFor("u-1", "campaign:update", "campaign:1")).allow).toBe(true);
    expect((await g.canOnEachFor("u-1", "campaign:update", ["campaign:1", "campaign:2"])).map((d) => d.allow)).toEqual([true, false]);
    expect(s.tokens()).toBe(1);
    await expect(g.canOnFor("u-2", "campaign:update", "campaign:1")).rejects.toBeInstanceOf(NotServedError);
  });

  it("guards DPoP-bound users with it, and refuses without a secret", async () => {
    const run = (g: ReturnType<typeof createGatekeeper>, sub: string) => new Promise<number>((resolve) => {
      const req = { headers: { authorization: "DPoP tok" }, params: { id: "campaign:1" }, gatekeeper: { sub, jkt: "thumb" } } as unknown as Req;
      let status = 0;
      const res = { status: (c: number) => { status = c; return res; }, setHeader: () => res, end: () => { resolve(status); return res; } };
      g.requirePermissionOn("campaign:update", () => "campaign:1")(req, res, () => resolve(200));
    });
    const s = onBehalfServer();
    const withSecret = createGatekeeper({ issuer: "https://auth.test/t/acme", audience: "api", clientId: "shop", clientSecret: "s3cret", fetch: s.f });
    expect(await run(withSecret, "u-1")).toBe(200);
    expect(await run(withSecret, "u-2")).toBe(403);
    const without = createGatekeeper({ issuer: "https://auth.test/t/acme", audience: "api", clientId: "shop", fetch: s.f });
    expect(await run(without, "u-1")).toBe(403);
  });
});
