// Headless sign-in for first-party apps as typed steps (FR-A22, ADR-0089):
// each step answers a result, problems are thrown as HeadlessProblem, and
// "complete" has already exchanged the code with the PKCE verifier.
import { challenge, random, same, tokenRequest, type TokenResponse } from "./pkce.js";

export interface HeadlessConfig {
  /** https://auth.<domain>/t/<tenant> */
  issuer: string;
  /** A client with headless_login (ADR-0082). */
  clientId: string;
  redirectUri: string;
  scope?: string;
  fetch?: typeof fetch;
}

export interface LegalDocument { kind: "terms" | "privacy"; version: string; url: string }

export type HeadlessResult =
  | { status: "complete"; tokens: TokenResponse }
  | { status: "mfa_required"; factor: "totp" | "email"; passkey: boolean }
  | { status: "terms_required"; documents: LegalDocument[] }
  | { status: "link_required"; provider: string }
  | { status: "code_sent" };

/** A problem answer (RFC 9457): type is the slug, e.g. "invalid-credentials", "locked", "captcha-required". */
export class HeadlessProblem extends Error {
  readonly type: string;
  readonly retryAfter?: number;
  readonly siteKey?: string;
  readonly ticket?: string;
  readonly deletesAt?: string;
  constructor(readonly status: number, readonly body: Record<string, unknown>, retryAfter: string | null) {
    const type = String(body.type ?? "").replace(/^\/errors\//, "") || `http-${status}`;
    super(`${type}: ${String(body.detail ?? body.title ?? "")}`);
    this.name = "HeadlessProblem";
    this.type = type;
    if (retryAfter) this.retryAfter = Number(retryAfter);
    if (typeof body.site_key === "string") this.siteKey = body.site_key;
    if (typeof body.ticket === "string") this.ticket = body.ticket;
    if (typeof body.deletes_at === "string") this.deletesAt = body.deletes_at;
  }
}

/** Runs the platform passkey API (navigator.credentials.get, or a native bridge) and returns the credential JSON. */
export type GetAssertion = (options: unknown) => Promise<unknown>;

export interface StartOptions { organization?: string; acrValues?: string; maxAge?: number }

export interface HeadlessSignIn {
  readonly flowId: string;
  readonly methods: string[];
  /** Pass to the provider's native SDK as the nonce before calling social(). */
  readonly providerNonce: string;
  password(identifier: string, password: string, captchaToken?: string): Promise<HeadlessResult>;
  sendCode(identifier: string, channel: "email" | "sms", captchaToken?: string): Promise<HeadlessResult>;
  verifyCode(code: string): Promise<HeadlessResult>;
  passkey(getAssertion: GetAssertion): Promise<HeadlessResult>;
  social(provider: "google" | "apple" | "microsoft", idToken: string, name?: string): Promise<HeadlessResult>;
  mfa(code: string): Promise<HeadlessResult>;
  mfaPasskey(getAssertion: GetAssertion): Promise<HeadlessResult>;
  acceptTerms(): Promise<HeadlessResult>;
  /** Keeps an account in its deletion grace period; then sign in again. */
  keep(ticket: string): Promise<void>;
}

/** startHeadless opens a flow for a fresh PKCE request. */
export async function startHeadless(config: HeadlessConfig, opts: StartOptions = {}): Promise<HeadlessSignIn> {
  const issuer = config.issuer.replace(/\/$/, "");
  const f = config.fetch ?? globalThis.fetch.bind(globalThis);
  const verifier = random();
  const state = random();

  async function post(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const resp = await f(`${issuer}/v1/auth/headless${path}`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body) });
    const out = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
    if (!resp.ok) throw new HeadlessProblem(resp.status, out, resp.headers.get("Retry-After"));
    return out;
  }

  const start = await post("/start", { client_id: config.clientId, redirect_uri: config.redirectUri, scope: config.scope ?? "openid",
    state, nonce: random(), code_challenge: await challenge(verifier), code_challenge_method: "S256",
    ...(opts.organization ? { organization: opts.organization } : {}), ...(opts.acrValues ? { acr_values: opts.acrValues } : {}),
    ...(opts.maxAge !== undefined ? { max_age: String(opts.maxAge) } : {}) });
  const flowId = String(start.flow_id);

  async function step(path: string, body: Record<string, unknown> = {}): Promise<HeadlessResult> {
    let out: Record<string, unknown>;
    try {
      out = await post(path, { flow_id: flowId, ...body });
    } catch (e) {
      if (e instanceof HeadlessProblem && e.type === "link-required") return { status: "link_required", provider: String(e.body.provider) };
      throw e;
    }
    switch (out.status) {
      case "complete":
        if (!same(String(out.state ?? ""), state)) throw new Error("state doesn't match this sign-in");
        return { status: "complete", tokens: await tokenRequest(f, issuer, { grant_type: "authorization_code", client_id: config.clientId,
          code: String(out.code), redirect_uri: config.redirectUri, code_verifier: verifier }) };
      case "mfa_required":
        return { status: "mfa_required", factor: out.factor as "totp" | "email", passkey: out.passkey === true };
      case "terms_required":
        return { status: "terms_required", documents: out.documents as LegalDocument[] };
      case "code_sent":
        return { status: "code_sent" };
    }
    throw new Error(`unexpected headless status ${String(out.status)}`);
  }

  async function withPasskey(begin: string, finish: string, getAssertion: GetAssertion) {
    const { options } = await post(begin, { flow_id: flowId });
    return step(finish, { credential: await getAssertion(options) });
  }

  return {
    flowId,
    methods: (start.methods as string[]) ?? [],
    providerNonce: String(start.provider_nonce ?? ""),
    password: (identifier, password, captchaToken) => step("/password", { identifier, password, captcha_token: captchaToken }),
    sendCode: (identifier, channel, captchaToken) => step("/code", { identifier, channel, captcha_token: captchaToken }),
    verifyCode: (code) => step("/code/verify", { code }),
    passkey: (getAssertion) => withPasskey("/passkey/begin", "/passkey", getAssertion),
    social: (provider, idToken, name) => step("/social", { provider, id_token: idToken, name }),
    mfa: (code) => step("/mfa", { code }),
    mfaPasskey: (getAssertion) => withPasskey("/mfa/passkey/begin", "/mfa", getAssertion),
    acceptTerms: () => step("/terms"),
    keep: async (ticket) => { await post("/keep", { flow_id: flowId, ticket }); },
  };
}
