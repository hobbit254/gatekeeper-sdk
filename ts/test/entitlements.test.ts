import { describe, expect, it } from "vitest";
import { fixedFetch, sdk, v } from "./helpers.js";

describe("entitlements (ADR-0098)", () => {
  it("exposes the plan and features from the token", async () => {
    const p = await sdk(fixedFetch().f).verify(v.entitlements.token);
    expect(p.entitlements).toEqual({ plan: v.entitlements.plan, features: v.entitlements.features });
    for (const f of v.entitlements.has as string[]) expect(p.hasFeature(f), f).toBe(true);
    for (const f of v.entitlements.lacks as string[]) expect(p.hasFeature(f), f).toBe(false);
  });

  it("has none without the claim", async () => {
    const p = await sdk(fixedFetch().f).verify(v.entitlements.plain);
    expect(p.entitlements).toBeUndefined();
    expect(p.hasFeature(v.entitlements.has[0])).toBe(false);
  });

  it("API keys have none", async () => {
    const p = await sdk(fixedFetch().f).verify(v.api_keys.cases[0].token);
    expect(p.hasFeature("anything")).toBe(false);
  });
});
