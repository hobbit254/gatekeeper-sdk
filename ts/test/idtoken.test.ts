import { CompactEncrypt, SignJWT, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { createGatekeeper } from "../src/index.js";

// FR-S15 (ADR-0121): servers verify ID tokens, plain or encrypted to the client.
describe("verifyIdToken", () => {
  it("decrypts, then checks signature, audience and nonce", async () => {
    const issuer = "https://auth.test/t/acme";
    const sig = await generateKeyPair("ES256");
    const enc = await generateKeyPair("RSA-OAEP-256", { modulusLength: 2048 });
    const jwks = { keys: [{ ...(await exportJWK(sig.publicKey)), kid: "k1", alg: "ES256", use: "sig" }] };
    const f = (async (input: string | URL | Request) =>
      String(input) === `${issuer}/.well-known/jwks.json` ? Response.json(jwks) : new Response("", { status: 404 })) as typeof fetch;
    const token = (aud: string) => new SignJWT({ nonce: "n-1", name: "Wanjiku" }).setProtectedHeader({ alg: "ES256", kid: "k1" })
      .setIssuer(issuer).setAudience(aud).setSubject("u1").setIssuedAt().setExpirationTime("5m").sign(sig.privateKey);
    const seal = async (jws: string) => new CompactEncrypt(new TextEncoder().encode(jws))
      .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM", cty: "JWT" }).encrypt(enc.publicKey);
    const g = createGatekeeper({ issuer, audience: "api", clientId: "web", fetch: f, decryptionKey: enc.privateKey });

    expect((await g.verifyIdToken(await seal(await token("web")), { nonce: "n-1" })).name).toBe("Wanjiku");
    expect((await g.verifyIdToken(await token("web"))).sub).toBe("u1"); // plain still works
    await expect(g.verifyIdToken(await seal(await token("web")), { nonce: "n-2" })).rejects.toThrow(/nonce/);
    await expect(g.verifyIdToken(await seal(await token("other")))).rejects.toThrow();
    const noKey = createGatekeeper({ issuer, audience: "api", clientId: "web", fetch: f });
    await expect(noKey.verifyIdToken(await seal(await token("web")))).rejects.toThrow(/decryptionKey/);
  });
});
