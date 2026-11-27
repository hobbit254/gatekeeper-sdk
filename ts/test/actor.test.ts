import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { createGatekeeper } from "../src/index.js";

// FR-M5 (ADR-0146): read-mode support access keeps only read permissions;
// write keeps them all; an act without mode is read.
describe("support session modes", () => {
  it("filters permissions in read mode", async () => {
    const issuer = "https://auth.test/t/acme";
    const key = await generateKeyPair("ES256");
    const jwks = { keys: [{ ...(await exportJWK(key.publicKey)), kid: "k1", alg: "ES256", use: "sig" }] };
    let withRead = true;
    const f = (async (input: string | URL | Request) => {
      const u = String(input);
      if (u === `${issuer}/.well-known/jwks.json`) return Response.json(jwks);
      if (u === `${issuer}/v1/clients/web/role-map`) {
        return Response.json({ rv: 1, roles: { ops: ["report:read", "report:list", "report:export"] },
          ...(withRead ? { read: ["report:read", "report:list"] } : {}) });
      }
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const token = (act?: Record<string, unknown>) => new SignJWT({ client_id: "web", jti: "j", roles: ["ops"], rv: 1, ...(act ? { act } : {}) })
      .setProtectedHeader({ alg: "ES256", kid: "k1", typ: "at+jwt" }).setIssuer(issuer).setAudience("api").setSubject("u1")
      .setIssuedAt().setExpirationTime("1m").sign(key.privateKey);
    const verify = async (act?: Record<string, unknown>) =>
      createGatekeeper({ issuer, audience: "api", clientId: "web", fetch: f }).verify(await token(act));

    expect((await verify()).permissions).toHaveLength(3);
    const read = await verify({ sub: "admin", mode: "read" });
    expect(read.actorMode).toBe("read");
    expect(read.can("report:list")).toBe(true);
    expect(read.can("report:export")).toBe(false);
    const write = await verify({ sub: "admin", mode: "write" });
    expect(write.actorMode).toBe("write");
    expect(write.can("report:export")).toBe(true);
    expect((await verify({ sub: "admin" })).can("report:export")).toBe(false);
    withRead = false;
    expect((await verify({ sub: "admin", mode: "read" })).permissions).toEqual(["report:read"]);
  });
});
