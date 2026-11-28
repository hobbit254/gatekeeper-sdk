import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { ApprovalError, createGatekeeper, createSharedDevice, type Principal } from "../src/index.js";

// FR-Z21 (ADR-0145): an approval verifies only for its requester and client,
// with typ approval+jwt and a published key; spending maps 409 and 422.
describe("approvals", () => {
  const issuer = "https://auth.test/t/acme";

  it("verifies and spends approvals", async () => {
    const key = await generateKeyPair("ES256");
    const other = await generateKeyPair("ES256");
    const jwks = { keys: [{ ...(await exportJWK(key.publicKey)), kid: "k1", alg: "ES256", use: "sig" }] };
    let spendStatus = 200;
    let spent: Record<string, unknown> = {};
    const f = (async (input: string | URL | Request, init?: RequestInit) => {
      const u = String(input);
      if (u === `${issuer}/.well-known/jwks.json`) return Response.json(jwks);
      if (u === `${issuer}/v1/approvals/spend`) {
        expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer at");
        spent = JSON.parse(String(init?.body));
        return Response.json({ approval_id: "a1", status: "spent", approver_id: "boss", amount: 300000 }, { status: spendStatus });
      }
      return new Response("", { status: 404 });
    }) as typeof fetch;
    const g = createGatekeeper({ issuer, audience: "api", clientId: "pos-api", fetch: f });
    const sign = (claims: Record<string, unknown>, opts: { typ?: string; priv?: CryptoKey; exp?: string } = {}) =>
      new SignJWT({ jti: "a1", req: "cashier", perm: "sale:refund", res: "sale:42", amt: 300000, cur: "KES", method: "pin", ...claims })
        .setProtectedHeader({ alg: "ES256", kid: "k1", typ: opts.typ ?? "approval+jwt" }).setIssuer(String(claims.iss ?? issuer))
        .setAudience(String(claims.aud ?? "pos")).setSubject("boss").setIssuedAt().setExpirationTime(opts.exp ?? "2m")
        .sign(opts.priv ?? key.privateKey);
    const p = { sub: "cashier", clientId: "pos" } as Principal;

    const a = await g.verifyApproval(await sign({}), p);
    expect(a).toMatchObject({ id: "a1", approver: "boss", requester: "cashier", permission: "sale:refund", amount: 300000, method: "pin" });
    for (const raw of [
      await sign({}, { typ: "at+jwt" }),
      await sign({}, { priv: other.privateKey }),
      await sign({ iss: "https://evil.test" }),
      await sign({ aud: "web" }),
      await sign({ req: "someone" }),
    ]) {
      await expect(g.verifyApproval(raw, p)).rejects.toMatchObject({ code: "mismatch" });
    }
    await expect(g.verifyApproval(await sign({}, { exp: "-5m" }), p)).rejects.toMatchObject({ code: "closed" });

    expect(await g.spendApproval("at", "tok", "sale:refund", "sale:42", 300000)).toMatchObject({ id: "a1", approver: "boss" });
    expect(spent).toEqual({ token: "tok", permission: "sale:refund", resource: "sale:42", amount: 300000 });
    await g.spendApproval("at", "tok", "sale:void", "sale:42");
    expect(spent).not.toHaveProperty("amount");
    spendStatus = 409;
    await expect(g.spendApproval("at", "tok", "sale:refund", "sale:42", 300000)).rejects.toBeInstanceOf(ApprovalError);
    await expect(g.spendApproval("at", "tok", "sale:refund", "sale:42", 300000)).rejects.toMatchObject({ code: "closed" });
    spendStatus = 422;
    await expect(g.spendApproval("at", "tok", "sale:refund", "sale:42", 300000)).rejects.toMatchObject({ code: "mismatch" });
    spendStatus = 502;
    await expect(g.spendApproval("at", "tok", "sale:refund", "sale:42", 300000)).rejects.toThrow(/unavailable/);
  });

  it("approves with a PIN on the shared device", async () => {
    const sent: { url: string; body: unknown; auth: string }[] = [];
    const f = (async (input: string | URL | Request, init?: RequestInit) => {
      sent.push({ url: String(input), body: JSON.parse(new TextDecoder().decode(init?.body as Uint8Array)),
        auth: new Headers(init?.headers).get("Authorization") ?? "" });
      return Response.json({ approval_id: "a1", status: "granted", method: "pin", approval_token: "tok" });
    }) as typeof fetch;
    const signer = { sign: async () => new Uint8Array(64), publicJWK: async () => ({ kty: "EC" }) };
    const device = createSharedDevice({ issuer, signer, deviceId: "d1", fetch: f });
    const out = await device.approveWithPin("a1", "boss", "5830");
    expect(out.approval_token).toBe("tok");
    expect(sent[0].url).toBe(`${issuer}/v1/devices/approvals/a1/approve`);
    expect(sent[0].body).toEqual({ approver_id: "boss", pin: "5830" });
    expect(sent[0].auth).toMatch(/^Device /);
  });
});
