import { compactVerify, importJWK } from "jose";
import { describe, expect, it } from "vitest";
import { createPushApprover, cryptoKeySigner, generatePushKey } from "../src/index.js";

// FR-A27 (ADR-0111): the app signs every device request with its approver key.
async function server() {
  const seen: { url: string; claims: Record<string, unknown>; kid?: string }[] = [];
  let jwk: JsonWebKey | undefined;
  const verify = async (jws: string) => {
    const { payload, protectedHeader } = await compactVerify(jws, await importJWK(jwk as never, "ES256"));
    return { claims: JSON.parse(new TextDecoder().decode(payload)), kid: protectedHeader.kid };
  };
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const h = new Headers(init?.headers);
    if (url.endsWith("/v1/me/push-approvers")) {
      if (h.get("authorization") !== "Bearer tok") return new Response("", { status: 401 });
      jwk = JSON.parse(String(init?.body)).public_key;
      return Response.json({ id: "a-1", name: "Pixel", recovery_codes: ["x"] }, { status: 201 });
    }
    if (url.endsWith("/v1/push/pending")) {
      const v = await verify(h.get("authorization")!.replace(/^Push /, ""));
      seen.push({ url, ...v });
      return Response.json({ challenges: [{ id: "c-1", client_id: "web", device: "Firefox on macOS", numbers: [12, 47, 83], created_at: "", expires_at: "" }] });
    }
    if (url.includes("/v1/push/challenges/")) {
      const v = await verify(JSON.parse(String(init?.body)).answer);
      seen.push({ url, ...v });
      return Response.json({ status: v.claims.number === 47 ? "approved" : "denied" });
    }
    return new Response("", { status: 404 });
  }) as typeof fetch;
  return { f, seen };
}

describe("push approver", () => {
  it("enrols, lists and answers with signed requests", async () => {
    const s = await server();
    const p = createPushApprover({ issuer: "https://auth.test/t/acme/", signer: cryptoKeySigner(await generatePushKey()), fetch: s.f });
    await expect(p.pending()).rejects.toThrow(/enrol/);
    expect((await p.enrol("tok", "Pixel")).recovery_codes).toEqual(["x"]);
    expect(p.approverId).toBe("a-1");
    const [c] = await p.pending();
    expect(c.numbers).toEqual([12, 47, 83]);
    expect(await p.approve(c.id, 47)).toBe("approved");
    expect(await p.deny(c.id, true)).toBe("denied");
    expect(s.seen.map((x) => x.kid)).toEqual(["a-1", "a-1", "a-1"]);
    expect(s.seen[0].claims.aud).toBe("https://auth.test/t/acme/v1/push");
    expect(new Set(s.seen.map((x) => x.claims.jti)).size).toBe(3);
    expect(s.seen[1].claims).toMatchObject({ challenge_id: "c-1", decision: "approve", number: 47 });
    expect(s.seen[2].claims).toMatchObject({ decision: "deny", reported: true });
  });

  it("surfaces refusals", async () => {
    const f = (async () => Response.json({ title: "Signature not accepted" }, { status: 401 })) as typeof fetch;
    const p = createPushApprover({ issuer: "https://auth.test/t/acme", approverId: "a-1", signer: cryptoKeySigner(await generatePushKey()), fetch: f });
    await expect(p.pending()).rejects.toMatchObject({ status: 401 });
  });
});
