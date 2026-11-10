import { afterEach, describe, expect, it, vi } from "vitest";
import { createClientCredentials, createGatekeeper, requireStepUp, type Req } from "../src/index.js";
import { fixedFetch, sdk, v } from "./helpers.js";

describe("impersonation (ADR-0058)", () => {
  it("exposes the actor and when it ends", async () => {
    const p = await sdk(fixedFetch().f).verify(v.impersonation.token);
    expect(p.actor).toBe(v.impersonation.actor);
    expect(p.impersonationEndsAt?.getTime()).toBe(v.impersonation.ends_at * 1000);
    const plain = await sdk(fixedFetch().f).verify(v.impersonation.plain);
    expect(plain.actor).toBeUndefined();
    expect(plain.impersonationEndsAt).toBeUndefined();
  });
});

describe("API keys (ADR-0057, ADR-0059)", () => {
  afterEach(() => vi.useRealTimers());

  for (const c of v.api_keys.cases as { name: string; token: string; permission: string; expect: string }[]) {
    it(c.name, async () => {
      let got = "reject";
      try {
        const p = await sdk(fixedFetch().f).verify(c.token);
        expect(p.apiKey).toBe(true);
        expect(p.sub).toBe(v.api_keys.subject);
        got = p.can(c.permission) ? "allow" : "deny";
      } catch {
        got = "reject";
      }
      expect(got).toBe(c.expect);
    });
  }

  it("caches an answer for a minute", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { f, calls } = fixedFetch();
    const g = sdk(f);
    const key = v.api_keys.cases[0].token;
    await g.verify(key);
    await g.verify(key);
    expect(calls.introspect).toBe(1);
    vi.setSystemTime(Date.now() + 61_000);
    await g.verify(key);
    expect(calls.introspect).toBe(2);
  });

  it("refuses when introspection fails", async () => {
    const g = createGatekeeper({ issuer: v.issuer, audience: v.audience, clientId: v.client_id, clientSecret: "wrong", fetch: fixedFetch().f });
    await expect(g.verify(v.api_keys.cases[0].token)).rejects.toThrow();
  });

  it("can never step up", async () => {
    const req: Req = { headers: {}, gatekeeper: await sdk(fixedFetch().f).verify(v.api_keys.cases[0].token) };
    let status = 0;
    const res = { status: (c: number) => { status = c; return res; }, setHeader: () => res, end: () => res };
    requireStepUp(3600)(req, res, () => { status = 200; });
    expect(status).toBe(401);
  });
});

describe("client credentials helper", () => {
  it("caches one token and shares one request", async () => {
    let calls = 0;
    const f = (async (_url: string | URL | Request, init?: RequestInit) => {
      calls++;
      const body = new URLSearchParams(String(init?.body));
      const auth = new Headers(init?.headers).get("authorization");
      if (auth !== "Basic " + Buffer.from("svc-job:s3cret").toString("base64") || body.get("grant_type") !== "client_credentials") {
        return new Response("{}", { status: 401 });
      }
      await new Promise((r) => setTimeout(r, 20));
      return Response.json({ access_token: "tok-1", token_type: "bearer", expires_in: 600 });
    }) as typeof fetch;
    const cc = createClientCredentials({ tokenUrl: "https://auth.test/t/acme/oauth2/token", clientId: "svc-job", clientSecret: "s3cret", audience: "api", fetch: f });
    const toks = await Promise.all([cc.token(), cc.token(), cc.token()]);
    expect(toks).toEqual(["tok-1", "tok-1", "tok-1"]);
    expect(await cc.token()).toBe("tok-1");
    expect(calls).toBe(1);
    const bad = createClientCredentials({ tokenUrl: "https://auth.test/t/acme/oauth2/token", clientId: "svc-job", clientSecret: "x", fetch: f });
    await expect(bad.token()).rejects.toThrow();
  });
});
