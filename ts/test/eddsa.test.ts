import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { createGatekeeper } from "../src/index.js";

// FR-S19 (ADR-0124): EdDSA ID tokens verify, access tokens stay ES256, and a
// header can't borrow the other ring's key.
describe("EdDSA ID tokens", () => {
  it("verifies EdDSA ID tokens only, with the matching key", async () => {
    const issuer = "https://auth.test/t/acme";
    const ec = await generateKeyPair("ES256");
    const ed = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    const jwks = { keys: [
      { ...(await exportJWK(ec.publicKey)), kid: "ec", alg: "ES256", use: "sig" },
      { ...(await exportJWK(ed.publicKey)), kid: "ed", alg: "EdDSA", use: "sig" },
    ] };
    const f = (async (input: string | URL | Request) => {
      const u = String(input);
      if (u === `${issuer}/.well-known/jwks.json`) return Response.json(jwks);
      if (u.startsWith(`${issuer}/v1/clients/web/role-map`)) return Response.json({ rv: 0, roles: {} });
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const g = createGatekeeper({ issuer, audience: "api", clientId: "web", fetch: f });
    const id = (alg: string, key: CryptoKey, kid: string) => new SignJWT({ nonce: "n" }).setProtectedHeader({ alg, kid })
      .setIssuer(issuer).setAudience("web").setSubject("u1").setIssuedAt().setExpirationTime("5m").sign(key);

    expect((await g.verifyIdToken(await id("EdDSA", ed.privateKey, "ed"), { nonce: "n" })).sub).toBe("u1");
    expect((await g.verifyIdToken(await id("ES256", ec.privateKey, "ec"))).sub).toBe("u1");
    await expect(g.verifyIdToken(await id("EdDSA", ed.privateKey, "ec"))).rejects.toThrow();
    await expect(g.verifyIdToken(await id("ES256", ec.privateKey, "ed"))).rejects.toThrow();

    const at = (alg: string, key: CryptoKey, kid: string) => new SignJWT({ client_id: "web", jti: "j", roles: [], rv: 0 })
      .setProtectedHeader({ alg, kid, typ: "at+jwt" }).setIssuer(issuer).setAudience("api").setSubject("u1").setIssuedAt()
      .setExpirationTime("5m").sign(key);
    expect((await g.verify(await at("ES256", ec.privateKey, "ec"))).sub).toBe("u1"); // the control: otherwise valid
    await expect(g.verify(await at("EdDSA", ed.privateKey, "ed"))).rejects.toThrow();
  });
});
