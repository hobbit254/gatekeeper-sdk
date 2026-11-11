// Web Crypto helpers shared by the browser and headless sign-in (ADR-0089).
// No Node imports: these modules run in browsers and React Native too.
import type { DPoPSigner } from "./dpop.js";

const b64url = (b: Uint8Array) => {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/** A 256-bit random value, base64url (43 characters). */
export function random(): string {
  return b64url(crypto.getRandomValues(new Uint8Array(32)));
}

/** The S256 code challenge for verifier (RFC 7636). */
export async function challenge(verifier: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}

/** Constant-time string comparison. */
export function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** A token endpoint answer. */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/** Posts form to the issuer's token endpoint (with a proof when dpop is set) and returns the tokens or throws. */
export async function tokenRequest(f: typeof fetch, issuer: string, form: Record<string, string>, dpop?: DPoPSigner): Promise<TokenResponse> {
  const init: RequestInit = {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString(),
  };
  const url = `${issuer}/oauth2/token`;
  const resp = await (dpop ? dpop.fetch(f, url, init) : f(url, init));
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(`token endpoint: ${(body as { error?: string }).error ?? resp.status}`);
  return body as TokenResponse;
}
