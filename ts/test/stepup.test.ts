import { describe, expect, it } from "vitest";
import { requirePermission, requireStepUp, type Req, type Res } from "../src/index.js";
import { fixedFetch, sdk, v } from "./helpers.js";

describe("step-up contract vectors", () => {
  for (const c of v.step_up as { name: string; token: string; max_age: number; fresh: boolean }[]) {
    it(c.name, async () => {
      const req: Req = { headers: {}, gatekeeper: await sdk(fixedFetch().f).verify(c.token) };
      const out = { code: 200, headers: {} as Record<string, string> };
      const res: Res = {
        status(code) { out.code = code; return res; },
        setHeader(n, val) { out.headers[n] = val; },
        end() {},
      };
      let passed = false;
      requireStepUp(c.max_age)(req, res, () => { passed = true; });
      expect(passed).toBe(c.fresh);
      if (!c.fresh) {
        expect(out.code).toBe(401);
        expect(out.headers["WWW-Authenticate"]).toBe(`Bearer error="insufficient_user_authentication", max_age="${c.max_age}"`);
      }
    });
  }
});

describe("per-permission step-up contract vectors (ADR-0097)", () => {
  const cases = v.permission_step_up as { name: string; token: string; permission: string; expect: string; max_age?: number }[];
  it("has cases", () => expect(cases.length).toBeGreaterThan(0));
  for (const c of cases) {
    it(c.name, async () => {
      const req: Req = { headers: {}, gatekeeper: await sdk(fixedFetch().f).verify(c.token) };
      const out = { code: 200, headers: {} as Record<string, string> };
      const res: Res = {
        status(code) { out.code = code; return res; },
        setHeader(n, val) { out.headers[n] = val; },
        end() {},
      };
      let passed = false;
      requirePermission(c.permission)(req, res, () => { passed = true; });
      expect(passed).toBe(c.expect === "allow");
      if (c.expect === "deny") expect(out.code).toBe(403);
      if (c.expect === "step_up") {
        expect(out.code).toBe(401);
        expect(out.headers["WWW-Authenticate"]).toBe(`Bearer error="insufficient_user_authentication", max_age="${c.max_age}", acr_values="mfa"`);
      }
    });
  }
});
