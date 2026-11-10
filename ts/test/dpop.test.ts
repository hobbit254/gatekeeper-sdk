import { describe, expect, it } from "vitest";
import { createGatekeeper, type Req } from "../src/index.js";
import { fixedFetch, v } from "./helpers.js";

const at = (nowMs: number) =>
  createGatekeeper({ issuer: v.issuer, audience: v.audience, clientId: v.client_id, clientSecret: v.client_secret,
    fetch: fixedFetch().f, now: () => nowMs });

describe("DPoP (RFC 9449, ADR-0070)", () => {
  it("checks the contract cases in order with one replay cache", async () => {
    const sdk = at(v.dpop.now * 1000);
    const p = await sdk.verify(v.dpop.token);
    expect(p.jkt).toBe(v.dpop.jkt);
    for (const c of v.dpop.cases as { name: string; proof: string; expect: string }[]) {
      let got = "allow";
      try {
        await sdk.verifyDPoP(p, v.dpop.token, c.proof, v.dpop.method, v.dpop.url);
      } catch {
        got = "reject";
      }
      expect(got, c.name).toBe(c.expect);
    }
  });

  it("refuses a bound token as Bearer, and DPoP for an unbound one", async () => {
    const mw = at(v.dpop.now * 1000).express();
    for (const auth of [`Bearer ${v.dpop.token}`, `DPoP ${v.dpop.token}`, `DPoP ${v.impersonation.plain}`]) {
      const req: Req = { headers: { authorization: auth, host: "api.example.test" }, method: "GET", originalUrl: "/orders", protocol: "https" };
      const status = await new Promise<number>((resolve) => {
        const res = { status: (c: number) => { resolve(c); return res; }, setHeader: () => res, end: () => res };
        mw(req, res, () => resolve(200));
      });
      expect(status, auth.slice(0, 12)).toBe(401);
    }
  });
});
