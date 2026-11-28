import { CompactEncrypt, SignJWT, UnsecuredJWT, exportJWK, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { AuthorizeError, LoginRequiredError, createBrowserClient } from "../src/browser.js";

const issuer = "https://auth.test/t/acme";
const redirectUri = "https://app.test/callback";
let key: CryptoKey;
let jwks: unknown;

beforeAll(async () => {
  const kp = await generateKeyPair("ES256");
  key = kp.privateKey as CryptoKey;
  jwks = { keys: [{ ...(await exportJWK(kp.publicKey)), kid: "k1", alg: "ES256", use: "sig" }] };
});

class MemoryStorage {
  m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

function idToken(nonce: string, extra: Record<string, unknown> = {}) {
  return new SignJWT({ nonce, ...extra }).setProtectedHeader({ alg: "ES256", kid: "k1" }).setIssuer(issuer)
    .setAudience("spa").setSubject("u1").setIssuedAt().setExpirationTime("5m").sign(key);
}

/** A fake Gatekeeper: JWKS, the token endpoint (code and refresh grants). */
function server(opts: { nonce?: (n: string) => string; accessTTL?: number; encryptTo?: CryptoKey; accessToken?: (n: number) => string } = {}) {
  const seen: { grant: string; body: URLSearchParams }[] = [];
  let nonce = "";
  let n = 0;
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === `${issuer}/.well-known/jwks.json`) return Response.json(jwks);
    if (url === `${issuer}/oauth2/token`) {
      const body = new URLSearchParams(String(init?.body));
      seen.push({ grant: body.get("grant_type") ?? "", body });
      n++;
      let id = await idToken(opts.nonce ? opts.nonce(nonce) : nonce);
      if (opts.encryptTo) {
        id = await new CompactEncrypt(new TextEncoder().encode(id))
          .setProtectedHeader({ alg: "ECDH-ES+A256KW", enc: "A256GCM", cty: "JWT", kid: "enc-1" }).encrypt(opts.encryptTo);
      }
      return Response.json({ access_token: opts.accessToken ? opts.accessToken(n) : `at-${n}`, refresh_token: `rt-${n}`, token_type: "Bearer", expires_in: opts.accessTTL ?? 600,
        id_token: id });
    }
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  return { f, seen, setNonce: (x: string) => { nonce = x; } };
}

function client(f: typeof fetch, storage = new MemoryStorage(), now = () => Date.now(), decryptionKey?: CryptoKey) {
  const went: string[] = [];
  const c = createBrowserClient({ issuer, clientId: "spa", redirectUri, scope: "openid profile offline_access", fetch: f,
    storage, navigate: (u) => { went.push(u); }, now, decryptionKey });
  return { c, went, storage };
}

describe("browser sign-in (FR-A21, ADR-0089)", () => {
  it("redirects with PKCE, state and nonce, then exchanges the code and checks the ID token", async () => {
    const s = server();
    const { c, went, storage } = client(s.f);
    await c.loginWithRedirect({ organization: "acme" });
    const auth = new URL(went[0]);
    expect(auth.origin + auth.pathname).toBe(`${issuer}/oauth2/authorize`);
    expect(auth.searchParams.get("code_challenge_method")).toBe("S256");
    expect(auth.searchParams.get("organization")).toBe("acme");
    expect(auth.searchParams.get("state")).toHaveLength(43);
    s.setNonce(auth.searchParams.get("nonce") ?? "");

    const user = await c.handleRedirectCallback(`${redirectUri}?code=c1&state=${auth.searchParams.get("state")}`);
    expect(user.sub).toBe("u1");
    expect(s.seen[0].body.get("code_verifier")).toHaveLength(43);
    expect(storage.m.size).toBe(0);
    expect(await c.getAccessToken()).toBe("at-1");
  });

  it("refuses a callback whose state isn't ours, and can't be replayed", async () => {
    const s = server();
    const { c, went } = client(s.f);
    await c.loginWithRedirect();
    const state = new URL(went[0]).searchParams.get("state");
    await expect(c.handleRedirectCallback(`${redirectUri}?code=c1&state=other`)).rejects.toThrow(/state/);
    await expect(c.handleRedirectCallback(`${redirectUri}?code=c1&state=${state}`)).rejects.toThrow(/no sign-in in progress/);
    expect(s.seen).toHaveLength(0);
  });

  it("refuses an ID token with another nonce", async () => {
    const s = server({ nonce: () => "someone-elses" });
    const { c, went } = client(s.f);
    await c.loginWithRedirect();
    const state = new URL(went[0]).searchParams.get("state");
    await expect(c.handleRedirectCallback(`${redirectUri}?code=c1&state=${state}`)).rejects.toThrow(/nonce/);
    await expect(c.getAccessToken()).rejects.toBeInstanceOf(LoginRequiredError);
  });

  it("refuses an ID token issued to another client", async () => {
    const s = server();
    const went: string[] = [];
    const other = createBrowserClient({ issuer, clientId: "other-spa", redirectUri, fetch: s.f, storage: new MemoryStorage(), navigate: (u) => { went.push(u); } });
    await other.loginWithRedirect();
    const auth = new URL(went[0]);
    s.setNonce(auth.searchParams.get("nonce") ?? "");
    await expect(other.handleRedirectCallback(`${redirectUri}?code=c1&state=${auth.searchParams.get("state")}`)).rejects.toThrow(/aud/);
  });

  it("turns authorize errors into AuthorizeError", async () => {
    const { c, went } = client(server().f);
    await c.loginWithRedirect({ prompt: "none" });
    const state = new URL(went[0]).searchParams.get("state");
    const err = await c.handleRedirectCallback(`${redirectUri}?error=consent_required&state=${state}`).catch((e) => e);
    expect(err).toBeInstanceOf(AuthorizeError);
    expect(err.error).toBe("consent_required");
  });

  it("refreshes once, shortly before expiry, and logs out with id_token_hint", async () => {
    let t = 1_000_000;
    const s = server({ accessTTL: 60 });
    const { c, went } = client(s.f, new MemoryStorage(), () => t);
    await c.loginWithRedirect();
    const auth = new URL(went[0]);
    s.setNonce(auth.searchParams.get("nonce") ?? "");
    await c.handleRedirectCallback(`${redirectUri}?code=c1&state=${auth.searchParams.get("state")}`);
    t += 45_000; // within 30 s of expiry
    const [a, b] = await Promise.all([c.getAccessToken(), c.getAccessToken()]);
    expect([a, b]).toEqual(["at-2", "at-2"]);
    expect(s.seen.filter((x) => x.grant === "refresh_token")).toHaveLength(1);
    expect(s.seen[1].body.get("refresh_token")).toBe("rt-1");

    await c.logout({ returnTo: "https://app.test/" });
    const out = new URL(went[1]);
    expect(out.pathname).toBe("/t/acme/oauth2/logout");
    expect(out.searchParams.get("id_token_hint")).toBeTruthy();
    expect(out.searchParams.get("post_logout_redirect_uri")).toBe("https://app.test/");
    await expect(c.getAccessToken()).rejects.toBeInstanceOf(LoginRequiredError);
  });
});

describe("encrypted ID tokens (FR-S15, ADR-0121)", () => {
  it("opens them with the client's key and keeps the signed token for the logout hint", async () => {
    const enc = await generateKeyPair("ECDH-ES+A256KW", { crv: "P-256", extractable: false });
    const s = server({ encryptTo: enc.publicKey as CryptoKey });
    const { c, went } = client(s.f, new MemoryStorage(), () => Date.now(), enc.privateKey as CryptoKey);
    await c.loginWithRedirect();
    const auth = new URL(went[0]);
    s.setNonce(auth.searchParams.get("nonce") ?? "");
    const user = await c.handleRedirectCallback(`${redirectUri}?code=c1&state=${auth.searchParams.get("state")}`);
    expect(user.sub).toBe("u1");
    await c.logout({ returnTo: "https://app.test/" });
    expect(new URL(went[1]).searchParams.get("id_token_hint")?.split(".")).toHaveLength(3);
  });

  it("refuses them without a key, or with another", async () => {
    const enc = await generateKeyPair("ECDH-ES+A256KW", { crv: "P-256" });
    const other = await generateKeyPair("ECDH-ES+A256KW", { crv: "P-256" });
    for (const k of [undefined, other.privateKey as CryptoKey]) {
      const s = server({ encryptTo: enc.publicKey as CryptoKey });
      const { c, went } = client(s.f, new MemoryStorage(), () => Date.now(), k);
      await c.loginWithRedirect();
      const auth = new URL(went[0]);
      s.setNonce(auth.searchParams.get("nonce") ?? "");
      await expect(c.handleRedirectCallback(`${redirectUri}?code=c1&state=${auth.searchParams.get("state")}`)).rejects.toThrow();
    }
  });
});

describe("support sessions in the browser (FR-M5, ADR-0159)", () => {
  async function signedIn(accessToken: (n: number) => string) {
    const s = server({ accessToken });
    const { c, went } = client(s.f);
    await c.loginWithRedirect();
    const auth = new URL(went[0]);
    s.setNonce(auth.searchParams.get("nonce") ?? "");
    await c.handleRedirectCallback(`${redirectUri}?code=c1&state=${auth.searchParams.get("state")}`);
    return c;
  }
  it("tells the page when its token is a support session's", async () => {
    const c = await signedIn(() => new UnsecuredJWT({ sub: "u1", act: { sub: "admin-1", ends_at: 1_900_000_000, mode: "read" } }).encode());
    expect(c.supportSession()).toEqual({ actor: "admin-1", mode: "read", readOnly: true, endsAt: new Date(1_900_000_000_000) });
  });
  it("is null for an ordinary session, and before sign-in", async () => {
    expect(client(server().f).c.supportSession()).toBeNull();
    const c = await signedIn(() => new UnsecuredJWT({ sub: "u1" }).encode());
    expect(c.supportSession()).toBeNull();
  });
});
