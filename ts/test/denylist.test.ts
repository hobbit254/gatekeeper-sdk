import { describe, expect, it } from "vitest";
import { fixedFetch, sdk, v } from "./helpers.js";

describe("denylist contract vectors", () => {
  const deny = async (sid: string, jti: string) => v.denylist.sids.includes(sid) || v.denylist.jtis.includes(jti);
  for (const c of v.denylist.cases as { name: string; token: string; permission: string; expect: string }[]) {
    it(c.name, async () => {
      let got = "reject";
      try {
        got = (await sdk(fixedFetch().f, deny).verify(c.token)).can(c.permission) ? "allow" : "deny";
      } catch {
        got = "reject";
      }
      expect(got).toBe(c.expect);
    });
  }
  it("an unreachable denylist refuses", async () => {
    const broken = async () => { throw new Error("redis down"); };
    await expect(sdk(fixedFetch().f, broken).verify(v.denylist.cases[0].token)).rejects.toThrow("denylist unavailable");
  });
});
