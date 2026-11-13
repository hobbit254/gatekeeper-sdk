// Runs against a real Gatekeeper started by tests/feature/sdk (ADR-0088,
// ADR-0089); skipped unless GK_LIVE_ISSUER is set.
import { describe, expect, it } from "vitest";
import { createAdminClient } from "../src/admin/index.js";
import { HeadlessProblem, startHeadless } from "../src/headless.js";
import { createPushApprover, cryptoKeySigner, generatePushKey } from "../src/push.js";

const env = process.env;
const live = env.GK_LIVE_ISSUER ? describe : describe.skip;
const config = () => ({ issuer: env.GK_LIVE_ISSUER!, clientId: env.GK_LIVE_CLIENT!, redirectUri: env.GK_LIVE_REDIRECT!, scope: "openid" });

live("live: headless sign-in (FR-A22)", () => {
  it("signs in with a password and gets tokens", async () => {
    const h = await startHeadless(config());
    expect(h.methods).toContain("password");
    const r = await h.password(env.GK_LIVE_EMAIL!, env.GK_LIVE_PASSWORD!);
    expect(r.status).toBe("complete");
    if (r.status === "complete") expect(r.tokens.access_token.split(".")).toHaveLength(3);
  });

  it("answers a wrong password as a typed problem", async () => {
    const h = await startHeadless(config());
    const err = await h.password(env.GK_LIVE_EMAIL!, "wrong password").catch((e) => e);
    expect(err).toBeInstanceOf(HeadlessProblem);
    expect(err.type).toBe("invalid-credentials");
  });
});

live("live: admin client (FR-D13)", () => {
  it("lists the tenant's clients", async () => {
    const admin = createAdminClient({ issuer: env.GK_LIVE_ISSUER!, token: () => env.GK_LIVE_ADMIN_TOKEN! });
    const { data, error } = await admin.GET("/v1/admin/clients", {});
    expect(error).toBeUndefined();
    expect(data?.items?.map((c) => c.client_id)).toContain(env.GK_LIVE_CLIENT);
  });
});

live("live: push approver (FR-A27)", () => {
  it("enrols and signs requests the server accepts", async () => {
    const h = await startHeadless(config());
    const r = await h.password(env.GK_LIVE_PUSH_EMAIL_TS!, env.GK_LIVE_PASSWORD!);
    expect(r.status).toBe("complete");
    if (r.status !== "complete") return;
    const p = createPushApprover({ issuer: env.GK_LIVE_ISSUER!, signer: cryptoKeySigner(await generatePushKey()) });
    const out = await p.enrol(r.tokens.access_token, "Live phone");
    expect(out.recovery_codes).toHaveLength(10);
    expect(await p.pending()).toEqual([]);
    await expect(p.approve("00000000-0000-0000-0000-000000000000", 10)).rejects.toMatchObject({ status: 404 });
  }, 20_000); // a real sign-in, an enrolment email and two signed calls, alongside the rest of the suite
});
