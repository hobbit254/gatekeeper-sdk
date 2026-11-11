// Sign-in by redirect for browser apps (FR-A21, ADR-0089). PKCE, state and
// nonce live in sessionStorage for the round trip only; tokens stay in memory.
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from "jose";
import { challenge, random, same, tokenRequest, type TokenResponse } from "./pkce.js";

export interface BrowserClientConfig {
  /** https://auth.<domain>/t/<tenant> */
  issuer: string;
  clientId: string;
  redirectUri: string;
  /** Default "openid". Add offline_access for silent renewal. */
  scope?: string;
  fetch?: typeof fetch;
  /** Defaults to window.sessionStorage. */
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">;
  /** Defaults to window.location.assign. */
  navigate?: (url: string) => void;
  /** Milliseconds; tests. */
  now?: () => number;
}

export interface LoginOptions {
  organization?: string;
  prompt?: "none" | "login" | "consent";
  uiLocales?: string;
  /** Other authorize parameters (acr_values, max_age, login_hint). */
  extra?: Record<string, string>;
}

/** The authorize endpoint answered with an error (access_denied, consent_required, …). */
export class AuthorizeError extends Error {
  constructor(public readonly error: string, public readonly description?: string) {
    super(description ? `${error}: ${description}` : error);
    this.name = "AuthorizeError";
  }
}

/** There are no tokens: call loginWithRedirect. */
export class LoginRequiredError extends Error {
  constructor() {
    super("sign-in required");
    this.name = "LoginRequiredError";
  }
}

interface Transaction { state: string; nonce: string; verifier: string }
interface Session { access: string; refresh?: string; idToken?: string; expiresAt: number }

export interface BrowserClient {
  loginWithRedirect(opts?: LoginOptions): Promise<void>;
  /** Finishes the redirect and returns the ID token's claims. */
  handleRedirectCallback(url?: string): Promise<JWTPayload>;
  /** A valid access token, refreshed shortly before expiry. */
  getAccessToken(): Promise<string>;
  logout(opts?: { returnTo?: string }): Promise<void>;
}

export function createBrowserClient(config: BrowserClientConfig): BrowserClient {
  const issuer = config.issuer.replace(/\/$/, "");
  const f = config.fetch ?? globalThis.fetch.bind(globalThis);
  const storage = config.storage ?? globalThis.sessionStorage;
  const navigate = config.navigate ?? ((u: string) => globalThis.location.assign(u));
  const now = config.now ?? (() => Date.now());
  const key = `gk.tx.${config.clientId}`;
  let session: Session | null = null;
  let refreshing: Promise<string> | null = null;

  async function verifyIDToken(raw: string, nonce: string): Promise<JWTPayload> {
    const resp = await f(`${issuer}/.well-known/jwks.json`);
    const { payload } = await jwtVerify(raw, createLocalJWKSet((await resp.json()) as JSONWebKeySet),
      { issuer, audience: config.clientId, currentDate: new Date(now()) });
    if (typeof payload.nonce !== "string" || !same(payload.nonce, nonce)) throw new Error("ID token nonce doesn't match this sign-in");
    return payload;
  }

  function keep(t: TokenResponse) {
    session = { access: t.access_token, refresh: t.refresh_token ?? session?.refresh, idToken: t.id_token ?? session?.idToken,
      expiresAt: now() + t.expires_in * 1000 };
  }

  return {
    async loginWithRedirect(opts = {}) {
      const tx: Transaction = { state: random(), nonce: random(), verifier: random() };
      storage.setItem(key, JSON.stringify(tx));
      const q = new URLSearchParams({ client_id: config.clientId, response_type: "code", redirect_uri: config.redirectUri,
        scope: config.scope ?? "openid", state: tx.state, nonce: tx.nonce, code_challenge: await challenge(tx.verifier),
        code_challenge_method: "S256", ...opts.extra });
      if (opts.organization) q.set("organization", opts.organization);
      if (opts.prompt) q.set("prompt", opts.prompt);
      if (opts.uiLocales) q.set("ui_locales", opts.uiLocales);
      navigate(`${issuer}/oauth2/authorize?${q}`);
    },

    async handleRedirectCallback(url = globalThis.location.href) {
      const params = new URL(url).searchParams;
      const stored = storage.getItem(key);
      storage.removeItem(key); // one use, whatever happens next
      if (!stored) throw new Error("no sign-in in progress");
      const tx = JSON.parse(stored) as Transaction;
      if (!same(params.get("state") ?? "", tx.state)) throw new Error("state doesn't match this sign-in");
      if (params.get("error")) throw new AuthorizeError(params.get("error") ?? "", params.get("error_description") ?? undefined);
      const t = await tokenRequest(f, issuer, { grant_type: "authorization_code", client_id: config.clientId,
        code: params.get("code") ?? "", redirect_uri: config.redirectUri, code_verifier: tx.verifier });
      if (!t.id_token) throw new Error("no ID token: request the openid scope");
      const claims = await verifyIDToken(t.id_token, tx.nonce);
      keep(t);
      return claims;
    },

    async getAccessToken() {
      if (!session) throw new LoginRequiredError();
      if (session.expiresAt - 30_000 > now()) return session.access;
      if (!session.refresh) {
        session = null;
        throw new LoginRequiredError();
      }
      refreshing ??= tokenRequest(f, issuer, { grant_type: "refresh_token", client_id: config.clientId, refresh_token: session.refresh })
        .then((t) => { keep(t); return t.access_token; })
        .catch((e) => { session = null; throw e instanceof Error ? new LoginRequiredError() : e; })
        .finally(() => { refreshing = null; });
      return refreshing;
    },

    async logout(opts = {}) {
      const q = new URLSearchParams({ client_id: config.clientId });
      if (session?.idToken) q.set("id_token_hint", session.idToken);
      if (opts.returnTo) q.set("post_logout_redirect_uri", opts.returnTo);
      session = null;
      navigate(`${issuer}/oauth2/logout?${q}`);
    },
  };
}
