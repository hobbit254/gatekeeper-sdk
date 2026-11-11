// DPoP proofs for the browser client and the client-credentials helper
// (RFC 9449, ADR-0096). No Node imports: this runs in browsers too.
import { SignJWT, calculateJwkThumbprint, exportJWK, type JWK } from "jose";
import { random } from "./pkce.js";

/** Where the browser keeps its key pair between page loads. */
export interface DPoPKeyStore {
  load(): Promise<CryptoKeyPair | undefined>;
  save(key: CryptoKeyPair): Promise<void>;
  delete(): Promise<void>;
}

/** Signs proofs with one P-256 key and remembers each server's latest DPoP-Nonce. */
export interface DPoPSigner {
  /** The key's RFC 7638 thumbprint: the dpop_jkt authorize parameter. */
  thumbprint(): Promise<string>;
  /** A proof for method and url; token adds ath (calls to APIs). */
  proof(method: string, url: string, token?: string): Promise<string>;
  /** fetch with a proof, retried once when the server asks for a nonce. */
  fetch(f: typeof fetch, url: string, init: RequestInit, token?: string): Promise<Response>;
}

const b64url = (b: Uint8Array) => {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** A new ES256 key pair whose private half can sign but can't be exported. */
export function generateDPoPKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

export function dpopSigner(key: CryptoKeyPair): DPoPSigner {
  const nonces = new Map<string, string>(); // origin → latest nonce
  let jwk: Promise<JWK> | undefined;
  const publicJWK = () => (jwk ??= exportJWK(key.publicKey).then(({ kty, crv, x, y }) => ({ kty, crv, x, y })));

  async function proof(method: string, url: string, token?: string): Promise<string> {
    const u = new URL(url);
    const claims: Record<string, string> = { jti: random(), htm: method.toUpperCase(), htu: u.origin + u.pathname };
    const nonce = nonces.get(u.origin);
    if (nonce) claims.nonce = nonce;
    if (token) claims.ath = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))));
    return new SignJWT(claims).setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await publicJWK() }).setIssuedAt()
      .sign(key.privateKey);
  }

  async function asksForNonce(r: Response): Promise<boolean> {
    if (r.status === 401) return /error="use_dpop_nonce"/.test(r.headers.get("www-authenticate") ?? "");
    if (r.status !== 400) return false;
    const body = (await r.clone().json().catch(() => ({}))) as { error?: string };
    return body.error === "use_dpop_nonce";
  }

  return {
    thumbprint: async () => calculateJwkThumbprint(await publicJWK(), "sha256"),
    proof,
    async fetch(f, url, init, token) {
      const origin = new URL(url).origin;
      for (let attempt = 0; ; attempt++) {
        const headers = new Headers(init.headers);
        headers.set("DPoP", await proof(init.method ?? "GET", url, token));
        if (token) headers.set("Authorization", `DPoP ${token}`);
        const r = await f(url, { ...init, headers });
        const n = r.headers.get("dpop-nonce");
        if (n) nonces.set(origin, n);
        if (attempt === 0 && n && (await asksForNonce(r))) continue; // RFC 9449 §8: retry once
        return r;
      }
    },
  };
}

/** Keeps the key pair in IndexedDB ("gatekeeper-dpop"), one per client id. */
export function indexedDBKeyStore(clientId: string): DPoPKeyStore {
  const open = () => new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open("gatekeeper-dpop", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("keys");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const run = async <T>(mode: IDBTransactionMode, op: (s: IDBObjectStore) => IDBRequest): Promise<T> => {
    const db = await open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const req = op(db.transaction("keys", mode).objectStore("keys"));
        req.onsuccess = () => resolve(req.result as T);
        req.onerror = () => reject(req.error);
      });
    } finally {
      db.close();
    }
  };
  return {
    load: () => run<CryptoKeyPair | undefined>("readonly", (s) => s.get(clientId)),
    save: (k) => run<void>("readwrite", (s) => s.put(k, clientId)),
    delete: () => run<void>("readwrite", (s) => s.delete(clientId)),
  };
}
