import { describe, expect, it } from "vitest";
import { HeadlessProblem, startHeadless } from "../src/headless.js";

const issuer = "https://auth.test/t/acme";

/** A scripted headless server: answers[path] is a function of the body. */
function server(answers: Record<string, (body: Record<string, unknown>) => Response>) {
  const seen: { path: string; body: Record<string, unknown> }[] = [];
  let state = "";
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === `${issuer}/oauth2/token`) {
      const form = new URLSearchParams(String(init?.body));
      seen.push({ path: "token", body: Object.fromEntries(form) });
      return Response.json({ access_token: "at", token_type: "Bearer", expires_in: 600, refresh_token: "rt" });
    }
    const path = url.replace(`${issuer}/v1/auth/headless`, "");
    const body = JSON.parse(String(init?.body ?? "{}"));
    seen.push({ path, body });
    if (path === "/start") {
      state = body.state;
      return Response.json({ flow_id: "f1", expires_in: 600, methods: ["password", "passkey"], provider_nonce: "pn" }, { status: 201 });
    }
    const a = answers[path];
    if (!a) return Response.json({ type: "/errors/not-found" }, { status: 404 });
    const r = a(body);
    return r.status === 299 ? Response.json({ status: "complete", code: "c1", state }) : r;
  }) as typeof fetch;
  return { f, seen };
}
const complete = () => new Response(null, { status: 299 });
const problem = (status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) =>
  Response.json(body, { status, headers });

describe("headless steps (FR-A22, ADR-0089)", () => {
  it("signs in with a password and exchanges the code with the verifier", async () => {
    const s = server({ "/password": complete });
    const h = await startHeadless({ issuer, clientId: "app", redirectUri: "app:/cb", fetch: s.f });
    expect(h.methods).toEqual(["password", "passkey"]);
    expect(h.providerNonce).toBe("pn");
    const r = await h.password("a@b.c", "pw");
    expect(r).toMatchObject({ status: "complete", tokens: { access_token: "at" } });
    const start = s.seen[0].body;
    expect(start.code_challenge_method).toBe("S256");
    const token = s.seen.find((x) => x.path === "token")!.body;
    expect(token.code).toBe("c1");
    expect(String(token.code_verifier)).toHaveLength(43);
  });

  it("walks the second factor and the terms", async () => {
    const s = server({
      "/password": () => Response.json({ status: "mfa_required", factor: "totp", passkey: true }),
      "/mfa/passkey/begin": () => Response.json({ options: { publicKey: { challenge: "x" } } }),
      "/mfa": (b) => b.credential ? Response.json({ status: "terms_required", documents: [{ kind: "terms", version: "v1", url: "https://t" }] }) : problem(400, {}),
      "/terms": complete,
    });
    const h = await startHeadless({ issuer, clientId: "app", redirectUri: "app:/cb", fetch: s.f });
    expect(await h.password("a@b.c", "pw")).toEqual({ status: "mfa_required", factor: "totp", passkey: true });
    let asked: unknown;
    const r = await h.mfaPasskey(async (o) => { asked = o; return { id: "cred" }; });
    expect(asked).toEqual({ publicKey: { challenge: "x" } });
    expect(r).toEqual({ status: "terms_required", documents: [{ kind: "terms", version: "v1", url: "https://t" }] });
    expect((await h.acceptTerms()).status).toBe("complete");
  });

  it("answers link-required as a result and other problems as HeadlessProblem", async () => {
    const s = server({
      "/social": () => problem(409, { type: "/errors/link-required", provider: "google" }),
      "/password": () => problem(429, { type: "/errors/locked", title: "Sign-in paused" }, { "Retry-After": "120" }),
      "/code": () => problem(400, { type: "/errors/captcha-required", site_key: "sk" }),
    });
    const h = await startHeadless({ issuer, clientId: "app", redirectUri: "app:/cb", fetch: s.f });
    expect(await h.social("google", "idt")).toEqual({ status: "link_required", provider: "google" });
    const locked = await h.password("a@b.c", "pw").catch((e) => e);
    expect(locked).toBeInstanceOf(HeadlessProblem);
    expect(locked).toMatchObject({ type: "locked", status: 429, retryAfter: 120 });
    await expect(h.sendCode("a@b.c", "email")).rejects.toMatchObject({ type: "captcha-required", siteKey: "sk" });
  });

  it("refuses a code for another request's state", async () => {
    const s = server({ "/password": () => Response.json({ status: "complete", code: "c1", state: "not-ours" }) });
    const h = await startHeadless({ issuer, clientId: "app", redirectUri: "app:/cb", fetch: s.f });
    await expect(h.password("a@b.c", "pw")).rejects.toThrow(/state/);
    expect(s.seen.some((x) => x.path === "token")).toBe(false);
  });

  it("throws when the client can't sign in headless", async () => {
    const f = (async () => Response.json({ type: "/errors/headless-not-allowed" }, { status: 403 })) as typeof fetch;
    await expect(startHeadless({ issuer, clientId: "web", redirectUri: "x", fetch: f })).rejects.toMatchObject({ type: "headless-not-allowed" });
  });
});
