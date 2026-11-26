import { describe, expect, it } from "vitest";
import { requirePermission, type Req, type Res } from "../src/index.js";
import { fixedFetch, sdk, v } from "./helpers.js";

function res() {
  const r = { code: 0, headers: {} as Record<string, string>, body: "" };
  const api: Res = {
    status(c) { r.code = c; return api; },
    setHeader(n, val) { r.headers[n] = val; },
    end(b) { r.body = b ?? ""; },
  };
  return { r, api };
}

const viewer = v.cases.find((c: { name: string }) => c.name === "viewer may read").token as string;

describe("express middleware", () => {
  it("401 without a bearer token", async () => {
    const { r, api } = res();
    sdk(fixedFetch().f).express()({ headers: {} }, api, () => { throw new Error("must not pass"); });
    expect(r.code).toBe(401);
    expect(r.headers["WWW-Authenticate"]).toBe("Bearer");
  });

  it("401 invalid_token for a bad token", async () => {
    const { r, api } = res();
    await new Promise<void>((done) => {
      api.end = () => { done(); return undefined; };
      sdk(fixedFetch().f).express()({ headers: { authorization: "Bearer not.a.jwt" } }, api, () => done());
    });
    expect(r.code).toBe(401);
    expect(r.headers["WWW-Authenticate"]).toBe('Bearer error="invalid_token"');
  });

  it("stores the principal; requirePermission allows and forbids", async () => {
    const req: Req = { headers: { authorization: `Bearer ${viewer}` } };
    await new Promise<void>((done, fail) => sdk(fixedFetch().f).express()(req, res().api, (e) => (e ? fail(e) : done())));
    expect(req.gatekeeper?.sub).toBe("0192f3a1-7c2e-7d3a-9b1f-3a4c5d6e7f80");
    expect(req.gatekeeper?.roles).toEqual(["viewer"]);

    let passed = false;
    requirePermission("subscriber:read")(req, res().api, () => { passed = true; });
    expect(passed).toBe(true);
    const denied = res();
    requirePermission("subscriber:delete")(req, denied.api, () => { throw new Error("must not pass"); });
    expect(denied.r.code).toBe(403);
  });
});

describe("role map cache", () => {
  it("is fetched once while rv is current", async () => {
    const { f, calls } = fixedFetch();
    const g = sdk(f);
    await g.verify(viewer);
    await g.verify(viewer);
    expect(calls.roleMap).toBe(1);
  });

  it("is refetched when a token's rv is newer", async () => {
    const stale = { ...v.role_map, rv: 2, roles: { viewer: [] } };
    const { f, calls } = fixedFetch([stale, v.role_map]);
    const g = sdk(f);
    expect((await g.verify(viewer)).can("subscriber:read")).toBe(false); // first fetch returns the stale rv 2 map
    expect((await g.verify(viewer)).can("subscriber:read")).toBe(true); // token rv 3 > cached 2: refetched
    expect(calls.roleMap).toBe(2);
  });

  it("an organization's map is cached until a token carries a newer orv (ADR-0142)", async () => {
    const tok = v.org_roles.cases[0].token; // org acme, orv 2
    const stale = { ...v.org_roles.role_maps.acme, orv: 1, roles: {} };
    const { f, calls } = fixedFetch([v.role_map], { acme: [stale, v.org_roles.role_maps.acme] });
    const g = sdk(f);
    expect((await g.verify(tok)).can("invoice:read")).toBe(false); // the stale orv 1 map
    expect((await g.verify(tok)).can("invoice:read")).toBe(true); // token orv 2 > cached 1: refetched
    expect((await g.verify(tok)).orv).toBe(2);
    expect(calls.orgMap).toBe(2);
    expect(calls.roleMap).toBe(0);
  });

  it("concurrent verifies share one fetch", async () => {
    const { f, calls } = fixedFetch();
    const g = sdk(f);
    await Promise.all([g.verify(viewer), g.verify(viewer), g.verify(viewer)]);
    expect(calls.roleMap).toBe(1);
  });
});
