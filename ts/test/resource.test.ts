import { describe, expect, it } from "vitest";
import { createGatekeeper, type Req } from "../src/index.js";

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
