import { describe, expect, it } from "vitest";
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
