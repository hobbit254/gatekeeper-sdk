import { compactVerify, importJWK } from "jose";
import { describe, expect, it } from "vitest";
import { createSharedDevice, cryptoKeySigner, DeviceError, generatePushKey, bodyHash } from "../src/index.js";

// Shared devices (FR-A45, FR-A46, ADR-0144): every request is signed over its URL and body.

const issuer = "https://auth.example.test/t/acme";

function server(answers: Record<string, Response | (() => Response)>) {
  const calls: { url: string; auth: string; body: Uint8Array }[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    calls.push({ url, auth: new Headers(init?.headers).get("authorization") ?? "", body: init?.body as Uint8Array });
    const a = answers[url.replace(issuer, "")];
    return typeof a === "function" ? a() : a ?? new Response("{}", { status: 404 });
  }) as typeof fetch;
  return { f, calls };
}

describe("a shared device", () => {
  it("claims with its public key, then signs each request for its URL and body", async () => {
    const keys = await generatePushKey();
    const signer = cryptoKeySigner(keys);
    const { f, calls } = server({
      "/v1/devices/claim": Response.json({ device_id: "dev-1", name: "Front till", client_id: "pos" }),
      "/v1/devices/pin-sign-in": Response.json({ access_token: "at", token_type: "Bearer", expires_in: 900, sid: "s1", session_expires_at: "2026-11-26T18:00:00Z" }),
    });
    const d = createSharedDevice({ issuer, signer, fetch: f });
    await expect(d.pinSignIn("u1", "4829")).rejects.toThrow(DeviceError);
    const claimed = await d.claim("K7QM-2XRP");
    expect(claimed.device_id).toBe("dev-1");
    expect(d.deviceId).toBe("dev-1");
    const claimBody = JSON.parse(new TextDecoder().decode(calls[0].body));
    expect(claimBody.public_jwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(claimBody.public_jwk.d).toBeUndefined();

    const s = await d.pinSignIn("u1", "4829");
    expect(s.sid).toBe("s1");
    const call = calls[1];
    expect(call.auth.startsWith("Device ")).toBe(true);
    const pub = await importJWK(claimBody.public_jwk, "ES256");
    const { payload, protectedHeader } = await compactVerify(call.auth.slice(7), pub);
    const claims = JSON.parse(new TextDecoder().decode(payload));
    expect(protectedHeader.kid).toBe("dev-1");
    expect(claims.aud).toBe(`${issuer}/v1/devices/pin-sign-in`);
    expect(claims.bh).toBe(await bodyHash(call.body));
    expect(Math.abs(claims.iat - Date.now() / 1000)).toBeLessThan(5);
    const again = await compactVerify((await (async () => { await d.pinSignIn("u1", "4829").catch(() => undefined); return calls[2].auth; })()).slice(7), pub);
    expect(JSON.parse(new TextDecoder().decode(again.payload)).jti).not.toBe(claims.jti);
  });

  it("says why a PIN was refused", async () => {
    const signer = cryptoKeySigner(await generatePushKey());
    const { f } = server({
      "/v1/devices/pin-sign-in": () => new Response(JSON.stringify({ type: "/errors/pin-locked", title: "PIN locked", detail: "Too many wrong PINs" }),
        { status: 423, headers: { "Retry-After": "840" } }),
      "/v1/devices/pin-sessions/renew": () => new Response(JSON.stringify({ type: "/errors/not-accepted", title: "Not accepted" }), { status: 401 }),
      "/v1/devices/pin-sign-out": () => new Response(null, { status: 204 }),
    });
    const d = createSharedDevice({ issuer, signer, deviceId: "dev-1", fetch: f });
    const err = await d.pinSignIn("u1", "0000").catch((e: unknown) => e) as DeviceError;
    expect(err).toBeInstanceOf(DeviceError);
    expect([err.status, err.code, err.retryAfter]).toEqual([423, "pin-locked", 840]);
    const idle = await d.renewPinSession("s1").catch((e: unknown) => e) as DeviceError;
    expect([idle.status, idle.code]).toEqual([401, "not-accepted"]);
    await expect(d.pinSignOut("s1")).resolves.toBeUndefined();
  });
});
