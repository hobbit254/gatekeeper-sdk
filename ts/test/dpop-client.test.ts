import { EmbeddedJWK, SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, jwtVerify, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { createBrowserClient, type DPoPKeyStore } from "../src/browser.js";
import { createClientCredentials, generateDPoPKey } from "../src/index.js";

// FR-S12, FR-S13 (ADR-0096).
const issuer = "https://auth.test/t/acme";
let idKey: CryptoKey;
let jwks: unknown;

beforeAll(async () => {
  const kp = await generateKeyPair("ES256");
  idKey = kp.privateKey as CryptoKey;
  jwks = { keys: [{ ...(await exportJWK(kp.publicKey)), kid: "k1", alg: "ES256" }] };
});

async function proofOf(h: Headers) {
  const { payload, protectedHeader } = await jwtVerify(h.get("dpop") ?? "", EmbeddedJWK, { typ: "dpop+jwt" });
  return { claims: payload as Record<string, unknown>, jkt: await calculateJwkThumbprint(protectedHeader.jwk as JWK) };
}

/** A fake Gatekeeper that wants nonce "n-1" on every proof and answers 400/401 use_dpop_nonce otherwise. */
function server() {
  const log: { url: string; claims: Record<string, unknown>; jkt: string; auth: string | null }[] = [];
  let n = 0;
  let txNonce = "";
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === `${issuer}/.well-known/jwks.json`) return Response.json(jwks);
    const h = new Headers(init?.headers);
    const { claims, jkt } = await proofOf(h);
    log.push({ url, claims, jkt, auth: h.get("authorization") });
    const headers = { "DPoP-Nonce": "n-1" };
    if (claims.nonce !== "n-1") {
      return url.endsWith("/oauth2/token")
        ? Response.json({ error: "use_dpop_nonce" }, { status: 400, headers })
        : new Response("", { status: 401, headers: { ...headers, "WWW-Authenticate": 'DPoP error="use_dpop_nonce"' } });
    }
    if (!url.endsWith("/oauth2/token")) return Response.json({ ok: true }, { headers });
    n++;
    const id = await new SignJWT({ nonce: txNonce }).setProtectedHeader({ alg: "ES256", kid: "k1" }).setIssuer(issuer).setAudience("spa")
      .setSubject("u1").setIssuedAt().setExpirationTime("5m").sign(idKey);
    return Response.json({ access_token: `at-${n}`, refresh_token: `rt-${n}`, token_type: "DPoP", expires_in: 1, id_token: id }, { headers });
  }) as typeof fetch;
  return { f, log, setNonce: (x: string) => { txNonce = x; } };
}

class MemoryKeys implements DPoPKeyStore {
  k?: CryptoKeyPair;
  deleted = 0;
  async load() { return this.k; }
  async save(k: CryptoKeyPair) { this.k = k; }
  async delete() { this.k = undefined; this.deleted++; }
}

class MemoryStorage {
  m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

describe("browser DPoP (FR-S13)", () => {
  it("binds the code, the tokens and API calls to one non-extractable key", async () => {
    const s = server();
    const keys = new MemoryKeys();
    const storage = new MemoryStorage();
    const went: string[] = [];
    const c = createBrowserClient({ issuer, clientId: "spa", redirectUri: "https://app.test/cb", scope: "openid offline_access",
      fetch: s.f, storage, navigate: (u) => { went.push(u); }, dpop: true, dpopKeyStore: keys });

    await c.loginWithRedirect();
    expect(keys.k?.privateKey.extractable).toBe(false);
    const auth = new URL(went[0]);
    const jkt = await calculateJwkThumbprint(await exportJWK(keys.k!.publicKey));
    expect(auth.searchParams.get("dpop_jkt")).toBe(jkt);

    const tx = JSON.parse(storage.getItem("gk.tx.spa")!) as { state: string; nonce: string };
    s.setNonce(tx.nonce);
    await c.handleRedirectCallback(`https://app.test/cb?code=c1&state=${tx.state}`);
    expect(s.log.map((l) => l.claims.nonce ?? "")).toEqual(["", "n-1"]); // retried once for the nonce
    expect(s.log.every((l) => l.jkt === jkt && l.claims.htm === "POST" && l.claims.htu === `${issuer}/oauth2/token`)).toBe(true);

    // the token expires in 1 s, so the call refreshes first (with a proof), then calls the API
    s.log.length = 0;
    const api = "https://api.test/v1/things?page=2";
    const r = await c.fetchWithDPoP(api, { method: "GET" });
    expect(r.status).toBe(200);
    expect(s.log.map((l) => l.url)).toEqual([`${issuer}/oauth2/token`, api, api]);
    const call = s.log[2];
    expect(call.auth).toBe("DPoP at-2");
    expect(call.claims.htu).toBe("https://api.test/v1/things");
    expect(call.claims.ath).toBeTypeOf("string");
    expect(call.jkt).toBe(jkt);

    await c.logout();
    expect(keys.deleted).toBe(1);
    await c.loginWithRedirect();
    expect(new URL(went[2]).searchParams.get("dpop_jkt")).not.toBe(jkt); // a new key after logout
  });

  it("keeps the key across page loads", async () => {
    const keys = new MemoryKeys();
    const went: string[] = [];
    const mk = () => createBrowserClient({ issuer, clientId: "spa", redirectUri: "https://app.test/cb", fetch: server().f,
      storage: new MemoryStorage(), navigate: (u) => { went.push(u); }, dpop: true, dpopKeyStore: keys });
    await mk().loginWithRedirect();
    await mk().loginWithRedirect();
    const jkts = went.map((u) => new URL(u).searchParams.get("dpop_jkt"));
    expect(jkts[0]).toBe(jkts[1]);
  });

  it("refuses fetchWithDPoP without dpop", async () => {
    const c = createBrowserClient({ issuer, clientId: "spa", redirectUri: "https://app.test/cb", fetch: server().f,
      storage: new MemoryStorage(), navigate: () => undefined });
    await expect(c.fetchWithDPoP("https://api.test/")).rejects.toThrow(/dpop/);
  });
});

describe("client credentials with a DPoP key (FR-S12)", () => {
  it("binds the token, retries once for the nonce and signs API calls", async () => {
    const s = server();
    const key = await generateDPoPKey();
    const cc = createClientCredentials({ tokenUrl: `${issuer}/oauth2/token`, clientId: "batch", clientSecret: "s", fetch: s.f, dpopKey: key });
    const tok = await cc.token();
    expect(tok).toBe("at-1");
    expect(s.log).toHaveLength(2);
    const proof = await cc.proof("POST", "https://api.test/v1/jobs", tok);
    const { claims, jkt } = await proofOf(new Headers({ DPoP: proof }));
    expect(claims).toMatchObject({ htm: "POST", htu: "https://api.test/v1/jobs" });
    expect(claims.ath).toBeTypeOf("string");
    expect(jkt).toBe(s.log[0].jkt);
  });

  it("gives up after one retry and refuses proofs without a key", async () => {
    let calls = 0;
    const f = (async () => {
      calls++;
      return Response.json({ error: "use_dpop_nonce" }, { status: 400, headers: { "DPoP-Nonce": `n-${calls}` } });
    }) as typeof fetch;
    const cc = createClientCredentials({ tokenUrl: `${issuer}/oauth2/token`, clientId: "batch", clientSecret: "s", fetch: f,
      dpopKey: await generateDPoPKey() });
    await expect(cc.token()).rejects.toThrow(/400/);
    expect(calls).toBe(2);
    const plain = createClientCredentials({ tokenUrl: `${issuer}/oauth2/token`, clientId: "batch", clientSecret: "s", fetch: f });
    await expect(plain.proof("GET", "https://api.test/", "t")).rejects.toThrow(/dpopKey/);
  });
});
