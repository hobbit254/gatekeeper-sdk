import { describe, expect, it } from "vitest";
import { ApprovalError, type Approval, type Principal } from "../src/index.js";
import { fixedFetch, sdk, v } from "./helpers.js";

describe("contract vectors", () => {
  for (const c of v.cases as { name: string; token: string; permission: string; expect: string }[]) {
    it(c.name, async () => {
      let got = "reject";
      try {
        const p = await sdk(fixedFetch().f).verify(c.token);
        got = p.can(c.permission) ? "allow" : "deny";
      } catch {
        got = "reject";
      }
      expect(got).toBe(c.expect);
    });
  }
});

describe("contract vectors: organization roles (ADR-0142)", () => {
  for (const c of v.org_roles.cases as { name: string; token: string; permission: string; expect: string }[]) {
    it(c.name, async () => {
      let got = "reject";
      try {
        const p = await sdk(fixedFetch().f).verify(c.token);
        got = p.can(c.permission) ? "allow" : "deny";
      } catch {
        got = "reject";
      }
      expect(got).toBe(c.expect);
    });
  }
});

describe("contract: amount limits (ADR-0143)", () => {
  for (const c of v.amount_limits.cases as { name: string; token: string; permission: string; amount: number; expect: string }[]) {
    it(c.name, async () => {
      const p = await sdk(fixedFetch().f).verify(c.token);
      expect(p.canAmount(c.permission, c.amount)).toBe(c.expect);
      if (p.limits) expect(p.currency).toBe(p.orgId === "acme" ? v.amount_limits.currency.acme : v.amount_limits.currency.tenant);
    });
  }
});


// ADR-0152: approval tokens and support-session modes, the same in every SDK.
describe("contract: approvals (ADR-0145)", () => {
  const p = { sub: v.approvals.principal.sub, clientId: v.approvals.principal.client_id } as Principal;
  for (const c of v.approvals.cases as { name: string; token: string; expect: string; approval?: Record<string, unknown> }[]) {
    it(c.name, async () => {
      let got = "ok";
      let a: Approval | undefined;
      try {
        a = await sdk(fixedFetch().f).verifyApproval(c.token, p);
      } catch (e) {
        if (!(e instanceof ApprovalError)) throw e;
        got = e.code;
      }
      expect(got).toBe(c.expect);
      if (got === "ok") {
        const w = c.approval!;
        expect(a).toMatchObject({ id: w.id, approver: w.approver, requester: w.requester, permission: w.permission,
          resource: w.resource, method: w.method, amount: w.amount, currency: w.currency });
      }
    });
  }
});

describe("contract: support-session modes (ADR-0146)", () => {
  for (const c of v.support_modes.cases as { name: string; map: string; token: string; actor_mode: string; permissions: string[] }[]) {
    it(c.name, async () => {
      const maps = c.map === "support" ? [v.support_modes.role_map] : [v.role_map];
      const p = await sdk(fixedFetch(maps).f).verify(c.token);
      expect(p.actorMode ?? "").toBe(c.actor_mode);
      expect([...p.permissions].sort()).toEqual([...c.permissions].sort());
    });
  }
});
