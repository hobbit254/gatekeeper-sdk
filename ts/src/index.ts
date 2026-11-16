// Gatekeeper TypeScript SDK: verify access tokens offline, hydrate a
// Principal, resolve permissions from the client's role map and guard routes
// (docs/INTEGRATION.md, docs/TOKENS.md, ADR-0005, ADR-0038).
import { createHash } from "node:crypto";
import { dpopSigner } from "./dpop.js";
import { innerToken, type DecryptionKey } from "./jwe.js";
import {
  calculateJwkThumbprint, compactVerify, createLocalJWKSet, decodeProtectedHeader, errors, importJWK, jwtVerify,
  type JSONWebKeySet, type JWK, type JWTPayload,
} from "jose";

/** Configures one API. `issuer` is https://auth.<domain>/t/<tenant>. */
export interface GatekeeperConfig {
  issuer: string;
  /** This API's identifier; every token must carry it in `aud`. */
  audience: string;
  /** The client whose role map resolves permissions. */
  clientId: string;
  /** Confidential clients authenticate to the role-map endpoint with it. */
  clientSecret?: string;
  /** Injected fetch (tests, proxies). Defaults to the global fetch. */
  fetch?: typeof fetch;
  /** Clock skew allowed on exp, seconds (default and maximum 60). */
  leewaySec?: number;
  /** Optional revocation check (FR-S7, ADR-0048): resolve true to refuse the
   * token. Rejections refuse too (fail closed). With ioredis:
   * `(sid, jti) => redis.exists(`gk:deny:sid:${sid}`, `gk:deny:jti:${jti}`).then((n) => n > 0)` */
  denylist?: (sid: string, jti: string) => Promise<boolean>;
  /** This API's external origin (https://api.example.com) for checking DPoP
   * proofs behind a proxy; defaults to the request's own (ADR-0070). */
  publicUrl?: string;
  /** Opens ID tokens encrypted to this client in verifyIdToken (ADR-0121). */
  decryptionKey?: DecryptionKey;
  /** Injected clock in milliseconds (tests). */
  now?: () => number;
}

/** The authenticated subject of a request. */
export interface Principal {
  sub: string;
  tenantId: string;
  orgId?: string;
  clientId: string;
  roles: string[];
  permissions: string[];
  scopes: string[];
  amr: string[];
  authTime: Date;
  rv: number;
  sid: string;
  jti: string;
  /** The admin acting as `sub`, and when that ends; set only on impersonation tokens (ADR-0058). Show a banner. */
  actor?: string;
  impersonationEndsAt?: Date;
  /** True for a principal from a gk_live_ API key (ADR-0057); ownerType is "user" or "service_account". */
  apiKey?: boolean;
  ownerType?: string;
  /** The DPoP key the token is bound to (cnf.jkt), if any (ADR-0070). */
  jkt?: string;
  /** Seconds within which each held permission needs a second factor, from the role map (ADR-0097). */
  stepUp?: Record<string, number>;
  /** The customer's plan and features from the token; absent when the tenant set none (ADR-0098). */
  entitlements?: Entitlements;
  /** Exact key match; wildcards are already expanded in the role map. */
  can(permission: string): boolean;
  /** Whether the token's entitlements include feature. */
  hasFeature(feature: string): boolean;
}

/** A customer's plan and paid-for features (ADR-0098). */
export interface Entitlements {
  plan: string;
  features: string[];
}

function entitlements(e: unknown): Entitlements | undefined {
  const x = e as { plan?: unknown; features?: unknown } | undefined;
  if (typeof x?.plan !== "string" || !Array.isArray(x.features)) return undefined;
  return { plan: x.plan, features: x.features.filter((f): f is string => typeof f === "string") };
}

/** Every verification failure. */
export class InvalidTokenError extends Error {
  constructor(reason: string) {
    super(`gatekeeper: invalid token: ${reason}`);
    this.name = "InvalidTokenError";
  }
}

/** The minimal request and response shapes the middleware needs (Express-compatible). */
export interface Req {
  headers: Record<string, string | string[] | undefined>;
  gatekeeper?: Principal;
  /** Express fields, used to check DPoP proofs. */
  method?: string;
  originalUrl?: string;
  url?: string;
  protocol?: string;
}
export interface Res {
  status(code: number): Res;
  setHeader(name: string, value: string): unknown;
  end(body?: string): unknown;
}
export type Next = (err?: unknown) => void;
export type Middleware = (req: Req, res: Res, next: Next) => void;

/** The user has no live sign-in through this client, so Gatekeeper won't check for them (ADR-0119). */
export class NotServedError extends Error {
  constructor() {
    super("gatekeeper: the user has no live sign-in through this client");
    this.name = "NotServedError";
  }
}

export interface Gatekeeper {
  /** Runs the TOKENS.md checklist and returns the Principal. */
  verify(token: string): Promise<Principal>;
  /** Checks a request's DPoP proof for a DPoP-bound principal (RFC 9449, ADR-0070). */
  verifyDPoP(p: Principal, accessToken: string, proof: string, method: string, url: string): Promise<void>;
  /** Express middleware: verifies the token ("Bearer", or "DPoP" with a proof), or answers 401. */
  express(): Middleware;
  /** Asks Gatekeeper whether token's subject holds permission on resource ("campaign:42"); never cached (ADR-0108). */
  canOn(token: string, permission: string, resource: string): Promise<ResourceDecision>;
  /** canOn for many resources, in order, 200 to a request. */
  canOnEach(token: string, permission: string, resources: string[]): Promise<ResourceDecision[]>;
  /**
   * canOn for userId with this client's own credentials (scope authz:check), for users whose
   * tokens are DPoP-bound (ADR-0119). Rejects with NotServedError when the user has no live
   * sign-in through this client.
   */
  canOnFor(userId: string, permission: string, resource: string): Promise<ResourceDecision>;
  /** canOnFor for many resources, in order, 200 to a request. */
  canOnEachFor(userId: string, permission: string, resources: string[]): Promise<ResourceDecision[]>;
  /**
   * Checks an ID token issued to clientId: signature, iss, aud, exp and, when given, nonce.
   * An encrypted one is opened with opts.decryptionKey or the config's (ADR-0121).
   */
  verifyIdToken(raw: string, opts?: { nonce?: string; decryptionKey?: DecryptionKey }): Promise<JWTPayload>;
  /**
   * Guards a route with a resource check, after express(): 403 when denied, 401 with the
   * step-up challenge when a fresher second factor would allow it, 503 when Gatekeeper can't answer.
   * A DPoP-bound token can't be forwarded without its holder's proof, so for one it checks with the
   * client's credentials (canOnFor); without a clientSecret it is 403.
   */
  requirePermissionOn(permission: string, resource: (req: Req) => string): Middleware;
}

/** Gatekeeper's answer for one resource (FR-Z12). */
export interface ResourceDecision {
  allow: boolean;
  matched_by: string;
  /** Seconds within which a second factor would allow it. */
  max_age?: number;
}

const DPOP_SKEW_SEC = 60;
const DPOP_ALGS = ["ES256", "RS256", "EdDSA"];
const JTI_CAPACITY = 100_000;

/** A URL without query and fragment, as htu compares it. */
function htu(raw: string): string | undefined {
  try {
    const u = new URL(raw);
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return undefined;
  }
}

const JWKS_COOLDOWN_MS = 30_000;

interface RoleMap {
  rv: number;
  roles: Record<string, string[]>;
  step_up?: Record<string, number>; // seconds per sensitive permission (ADR-0097)
}

/** Returns an SDK instance for one API; safe to share across requests. */
export function createGatekeeper(config: GatekeeperConfig): Gatekeeper {
  const issuer = config.issuer.replace(/\/$/, "");
  const doFetch = config.fetch ?? fetch;
  const leeway = Math.min(config.leewaySec && config.leewaySec > 0 ? config.leewaySec : 60, 60);
  const now = config.now ?? Date.now;
  // shortcut: per process; replicas keep their own, so a proof could replay once per replica within 2 minutes.
  const jtis = new Map<string, number>();

  let keys: ReturnType<typeof createLocalJWKSet> | undefined;
  let keysInflight: Promise<boolean> | undefined;
  let lastJWKSFetch = 0;
  let roleMap: RoleMap | undefined;
  let roleMapInflight: Promise<RoleMap> | undefined;

  async function getJSON<T>(url: string, auth: boolean): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (auth && config.clientSecret) {
      headers.Authorization = "Basic " + Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64");
    }
    const res = await doFetch(url, { headers });
    if (res.status !== 200) throw new Error(`gatekeeper: fetch ${url}: status ${res.status}`);
    return (await res.json()) as T;
  }

  // refreshKeys refetches the JWKS at most every 30 s; concurrent callers share one fetch.
  function refreshKeys(): Promise<boolean> {
    if (keysInflight) return keysInflight;
    if (Date.now() - lastJWKSFetch < JWKS_COOLDOWN_MS) return Promise.resolve(false);
    lastJWKSFetch = Date.now();
    keysInflight = getJSON<JSONWebKeySet>(`${issuer}/.well-known/jwks.json`, false)
      .then((set) => { keys = createLocalJWKSet(set); return true; })
      .finally(() => { keysInflight = undefined; });
    return keysInflight;
  }

  async function verifySignature(token: string): Promise<JWTPayload> {
    if (!keys) await refreshKeys();
    if (!keys) throw new Error("no signing keys");
    const opts = { issuer, audience: config.audience, algorithms: ["ES256"], typ: "at+jwt", clockTolerance: leeway };
    try {
      return (await jwtVerify(token, keys!, opts)).payload;
    } catch (e) {
      // An unknown kid triggers one JWKS refetch, at most every 30 s.
      if (e instanceof errors.JWKSNoMatchingKey && (await refreshKeys())) {
        return (await jwtVerify(token, keys!, opts)).payload;
      }
      throw e;
    }
  }

  // verifyIdToken checks an ID token for this client, decrypting it first when encrypted (ADR-0121).
  async function verifyIdToken(raw: string, opts: { nonce?: string; decryptionKey?: DecryptionKey } = {}): Promise<JWTPayload> {
    const inner = await innerToken(raw, opts.decryptionKey ?? config.decryptionKey);
    if (!keys) await refreshKeys();
    if (!keys) throw new Error("no signing keys");
    const v = { issuer, audience: config.clientId, algorithms: ["ES256"], clockTolerance: leeway };
    const payload = await jwtVerify(inner, keys, v).catch(async (e: unknown) => {
      if (e instanceof errors.JWKSNoMatchingKey && (await refreshKeys())) return jwtVerify(inner, keys!, v);
      throw e;
    }).then((r) => r.payload);
    if (opts.nonce !== undefined && payload.nonce !== opts.nonce) throw new Error("gatekeeper: ID token nonce doesn't match");
    return payload;
  }

  async function permissions(roles: string[], rv: number): Promise<{ perms: string[]; stepUp?: Record<string, number> }> {
    if (!roleMap || rv > roleMap.rv) {
      // Single-flight: concurrent requests share one refetch.
      roleMapInflight ??= getJSON<RoleMap>(`${issuer}/v1/clients/${encodeURIComponent(config.clientId)}/role-map`, true)
        .finally(() => { roleMapInflight = undefined; });
      roleMap = await roleMapInflight;
    }
    const out = new Set<string>();
    for (const r of roles) for (const p of roleMap.roles[r] ?? []) out.add(p);
    let stepUp: Record<string, number> | undefined;
    for (const p of out) {
      const w = roleMap.step_up?.[p];
      if (w) (stepUp ??= {})[p] = w;
    }
    return { perms: [...out], stepUp };
  }

  // API keys: introspected with this API's client credentials, cached 60 s
  // (inactive 10 s); any failure refuses (ADR-0057, ADR-0059).
  const keyCache = new Map<string, { p?: Principal; until: number }>();
  async function verifyKey(key: string): Promise<Principal> {
    const id = createHash("sha256").update(key).digest("hex");
    let e = keyCache.get(id);
    if (!e || Date.now() >= e.until) {
      let r: Record<string, unknown>;
      try {
        const res = await doFetch(`${issuer}/oauth2/introspect`, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization: "Basic " + Buffer.from(`${config.clientId}:${config.clientSecret ?? ""}`).toString("base64"),
          },
          body: new URLSearchParams({ token: key }).toString(),
        });
        if (res.status !== 200) throw new Error(`status ${res.status}`);
        r = (await res.json()) as Record<string, unknown>;
      } catch (err) {
        throw new InvalidTokenError(`introspection failed: ${err instanceof Error ? err.message : err}`);
      }
      let p: Principal | undefined;
      if (r.active === true && r.token_type === "api_key") {
        const perms = strings(r.permissions);
        p = {
          sub: String(r.sub ?? ""), tenantId: String(r.tid ?? ""), clientId: "", roles: [], permissions: perms,
          scopes: typeof r.scope === "string" ? r.scope.split(" ").filter(Boolean) : [], amr: [], authTime: new Date(0),
          rv: 0, sid: "", jti: "", apiKey: true, ownerType: String(r.owner_type ?? ""), can: (x: string) => perms.includes(x),
          hasFeature: () => false,
        };
      }
      e = { p, until: Date.now() + (p ? 60_000 : 10_000) };
      keyCache.set(id, e);
    }
    if (!e.p) throw new InvalidTokenError("inactive API key");
    return e.p;
  }

  async function verify(token: string): Promise<Principal> {
    if (token.startsWith("gk_live_")) return verifyKey(token);
    let c: JWTPayload;
    try {
      c = await verifySignature(token);
    } catch (e) {
      throw new InvalidTokenError(e instanceof Error ? e.message : "verification failed");
    }
    if (config.denylist) {
      let denied: boolean;
      try {
        denied = await config.denylist(String(c.sid ?? ""), String(c.jti ?? ""));
      } catch {
        throw new InvalidTokenError("denylist unavailable"); // fail closed (ADR-0048)
      }
      if (denied) throw new InvalidTokenError("revoked");
    }
    const roles = strings(c.roles);
    const rv = typeof c.rv === "number" ? c.rv : 0;
    const { perms, stepUp } = await permissions(roles, rv);
    const ents = entitlements(c.entitlements);
    return {
      ...(stepUp ? { stepUp } : {}),
      sub: String(c.sub ?? ""),
      tenantId: String(c.tid ?? ""),
      orgId: typeof c.org === "string" ? c.org : undefined,
      clientId: String(c.client_id ?? ""),
      roles,
      permissions: perms,
      scopes: typeof c.scope === "string" ? c.scope.split(" ").filter(Boolean) : [],
      amr: strings(c.amr),
      authTime: new Date((typeof c.auth_time === "number" ? c.auth_time : 0) * 1000),
      rv,
      sid: String(c.sid ?? ""),
      jti: String(c.jti ?? ""),
      ...impersonation(c.act),
      ...(typeof (c.cnf as { jkt?: unknown } | undefined)?.jkt === "string" ? { jkt: (c.cnf as { jkt: string }).jkt } : {}),
      ...(ents ? { entitlements: ents } : {}),
      can: (p: string) => perms.includes(p),
      hasFeature: (f: string) => ents?.features.includes(f) ?? false,
    };
  }

  async function verifyDPoP(p: Principal, accessToken: string, proof: string, method: string, url: string): Promise<void> {
    const bad = (why: string) => new InvalidTokenError(`DPoP proof: ${why}`);
    if (!p.jkt) throw bad("the token is not DPoP-bound");
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(proof);
    } catch {
      throw bad("parse");
    }
    const jwk = header.jwk as JWK | undefined;
    if (header.typ !== "dpop+jwt" || !jwk || "d" in jwk || !DPOP_ALGS.includes(String(header.alg))) throw bad("header");
    let claims: Record<string, unknown>;
    try {
      const key = await importJWK(jwk, String(header.alg));
      const { payload } = await compactVerify(proof, key, { algorithms: DPOP_ALGS });
      claims = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;
    } catch {
      throw bad("signature");
    }
    const want = htu(url);
    if (!want || claims.htm !== method || typeof claims.htu !== "string" || htu(claims.htu) !== want) throw bad("htm or htu");
    const nowSec = now() / 1000;
    if (typeof claims.iat !== "number" || Math.abs(claims.iat - nowSec) > DPOP_SKEW_SEC) throw bad("iat");
    if (claims.ath !== createHash("sha256").update(accessToken).digest("base64url")) throw bad("ath");
    if ((await calculateJwkThumbprint(jwk, "sha256")) !== p.jkt) throw bad("another key");
    if (typeof claims.jti !== "string" || !claims.jti) throw bad("jti");
    const id = `${p.jkt}:${claims.jti}`;
    const t = now();
    if (jtis.size >= JTI_CAPACITY) for (const [k, until] of jtis) if (until < t) jtis.delete(k);
    if (jtis.size >= JTI_CAPACITY || (jtis.get(id) ?? 0) > t) throw bad("replayed"); // full: refuse rather than forget
    jtis.set(id, t + 2 * DPOP_SKEW_SEC * 1000);
  }

  async function authz<T>(token: string, path: string, body: unknown): Promise<T> {
    let res: Response;
    try {
      res = await doFetch(`${issuer}${path}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(body) });
    } catch (e) {
      throw new Error(`gatekeeper: resource check unavailable: ${String(e)}`);
    }
    if (res.status === 403) {
      const p = (await res.json().catch(() => ({}))) as { type?: string };
      if (typeof p.type === "string" && p.type.endsWith("user-not-served")) throw new NotServedError();
    }
    if (res.status !== 200) throw new Error(`gatekeeper: resource check unavailable: status ${res.status}`);
    return (await res.json()) as T;
  }
  let cc: { token: string; until: number } | undefined;
  let ccInflight: Promise<string> | undefined;
  async function clientToken(): Promise<string> {
    if (!config.clientSecret) throw new Error("gatekeeper: on-behalf checks need clientId and clientSecret");
    if (cc && now() < cc.until) return cc.token;
    ccInflight ??= (async () => {
      const form = new URLSearchParams({ grant_type: "client_credentials", scope: "authz:check" });
      if (config.audience) form.set("audience", config.audience);
      const res = await doFetch(`${issuer}/oauth2/token`, { method: "POST", body: form.toString(), headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret ?? "")}`).toString("base64") } });
      if (res.status !== 200) throw new Error(`gatekeeper: resource check unavailable: client credentials refused (${res.status})`);
      const t = (await res.json()) as { access_token: string; expires_in: number };
      cc = { token: t.access_token, until: now() + (t.expires_in - 60) * 1000 };
      return t.access_token;
    })().finally(() => { ccInflight = undefined; });
    return ccInflight;
  }
  const canOn = (token: string, permission: string, resource: string) =>
    authz<ResourceDecision>(token, "/v1/authz/check", { permission, resource });
  async function canOnEach(token: string, permission: string, resources: string[], userId?: string): Promise<ResourceDecision[]> {
    const out: ResourceDecision[] = [];
    for (let i = 0; i < resources.length; i += 200) {
      const chunk = resources.slice(i, i + 200);
      const r = await authz<{ results: ResourceDecision[] }>(token, "/v1/authz/check-batch",
        { checks: chunk.map((resource) => ({ permission, resource })), ...(userId ? { user_id: userId } : {}) });
      if (r.results.length !== chunk.length) throw new Error("gatekeeper: resource check unavailable: wrong number of answers");
      out.push(...r.results);
    }
    return out;
  }

  const canOnFor = async (userId: string, permission: string, resource: string) =>
    authz<ResourceDecision>(await clientToken(), "/v1/authz/check", { user_id: userId, permission, resource });
  const canOnEachFor = async (userId: string, permission: string, resources: string[]) =>
    canOnEach(await clientToken(), permission, resources, userId);

  return {
    verify,
    verifyDPoP,
    canOn,
    canOnEach: (token: string, permission: string, resources: string[]) => canOnEach(token, permission, resources),
    canOnFor,
    canOnEachFor,
    verifyIdToken,
    requirePermissionOn(permission, resource): Middleware {
      return (req, res, next) => {
        const header = req.headers.authorization;
        const token = typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : "";
        const p = req.gatekeeper;
        let decide: Promise<ResourceDecision>;
        if (p && token && !p.jkt) decide = canOn(token, permission, resource(req));
        else if (p && config.clientSecret) decide = canOnFor(p.sub, permission, resource(req)); // DPoP-bound (ADR-0119)
        else {
          res.status(403).end("forbidden");
          return;
        }
        decide.then((d) => {
          if (d.allow) return next();
          if (d.max_age) {
            res.setHeader("WWW-Authenticate", `Bearer error="insufficient_user_authentication", max_age="${d.max_age}", acr_values="mfa"`);
            res.status(401).end("step-up required");
            return;
          }
          res.status(403).end("forbidden");
        }, (e) => { if (e instanceof NotServedError) res.status(403).end("forbidden"); else res.status(503).end("authorization unavailable"); });
      };
    },
    express(): Middleware {
      return (req, res, next) => {
        const header = req.headers.authorization;
        const dpop = typeof header === "string" && header.startsWith("DPoP ");
        const raw = typeof header === "string" && (header.startsWith("Bearer ") || dpop) ? header.slice(dpop ? 5 : 7) : "";
        if (!raw) {
          res.setHeader("WWW-Authenticate", "Bearer");
          res.status(401).end("unauthorized");
          return;
        }
        let bound = false;
        verify(raw)
          .then(async (p) => {
            bound = !!p.jkt;
            if (bound !== dpop) throw new InvalidTokenError("wrong authorization scheme for this token");
            if (bound) {
              const proof = req.headers.dpop;
              const base = config.publicUrl?.replace(/\/$/, "") ?? `${req.protocol ?? "http"}://${String(req.headers.host ?? "")}`;
              const path = (req.originalUrl ?? req.url ?? "/").split("?")[0];
              await verifyDPoP(p, raw, typeof proof === "string" ? proof : "", req.method ?? "GET", base + path);
            }
            return p;
          })
          .then(
            (p) => { req.gatekeeper = p; next(); },
            (e) => {
              if (!(e instanceof InvalidTokenError)) return next(e); // JWKS or role map unreachable: a 5xx, not a 401
              res.setHeader("WWW-Authenticate", dpop || bound
                ? 'DPoP error="invalid_token", algs="ES256 RS256 EdDSA"' : 'Bearer error="invalid_token"');
              res.status(401).end("unauthorized");
            },
          );
      };
    },
  };
}

/** Answers 403 unless the request's Principal holds permission, and 401 with
 * the RFC 9470 challenge when the permission's step-up window from the role
 * map has passed (ADR-0097). Direct grants need /v1/authz/check (ADR-0005). */
export function requirePermission(permission: string): Middleware {
  return (req, res, next) => {
    const p = req.gatekeeper;
    if (!p?.can(permission)) {
      res.status(403).end("forbidden");
      return;
    }
    const window = p.stepUp?.[permission];
    const machine = p.apiKey === true || p.amr.length === 0; // never asked to step up (ADR-0056)
    if (window && !machine && !freshMFA(p, window)) {
      res.setHeader("WWW-Authenticate", `Bearer error="insufficient_user_authentication", max_age="${window}", acr_values="mfa"`);
      res.status(401).end("step-up required");
      return;
    }
    next();
  };
}

/** The Principal the express() middleware stored on req. */
export function getPrincipal(req: Req): Principal | undefined {
  return req.gatekeeper;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** Whether the principal signed in with a second factor ("mfa" in amr) within maxAgeSec (ADR-0046). */
export function freshMFA(p: Principal, maxAgeSec: number): boolean {
  return p.amr.includes("mfa") && Date.now() - p.authTime.getTime() <= maxAgeSec * 1000;
}

/** Answers 401 with the RFC 9470 challenge unless the principal has a second
 * factor within maxAgeSec. The client re-runs authorize with max_age and
 * acr_values=mfa, then retries. */
export function requireStepUp(maxAgeSec: number): Middleware {
  return (req, res, next) => {
    if (!req.gatekeeper || !freshMFA(req.gatekeeper, maxAgeSec)) {
      res.setHeader("WWW-Authenticate", `Bearer error="insufficient_user_authentication", max_age="${maxAgeSec}"`);
      res.status(401).end("step-up required");
      return;
    }
    next();
  };
}

function impersonation(act: unknown): { actor?: string; impersonationEndsAt?: Date } {
  if (!act || typeof act !== "object") return {};
  const a = act as { sub?: unknown; ends_at?: unknown };
  return {
    actor: typeof a.sub === "string" ? a.sub : undefined,
    impersonationEndsAt: typeof a.ends_at === "number" ? new Date(a.ends_at * 1000) : undefined,
  };
}

/** Fetches and caches an m2m access token (FR-M1, ADR-0059). */
export interface ClientCredentialsConfig {
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  audience?: string;
  fetch?: typeof fetch;
  /** A P-256 key pair (generateDPoPKey) that binds the token to it (FR-S12, ADR-0096). */
  dpopKey?: CryptoKeyPair;
}

export interface ClientCredentials {
  /** A token valid for at least another minute; concurrent calls share one request. */
  token(): Promise<string>;
  /** A DPoP proof for an API call made with token (needs dpopKey). */
  proof(method: string, url: string, token: string): Promise<string>;
}

/** Returns a token source for client credentials, bound to dpopKey when set. */
export function createClientCredentials(config: ClientCredentialsConfig): ClientCredentials {
  const doFetch = config.fetch ?? fetch;
  const dpop = config.dpopKey ? dpopSigner(config.dpopKey) : undefined;
  let cached: { token: string; until: number } | undefined;
  let inflight: Promise<string> | undefined;
  async function fetchToken(): Promise<string> {
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    if (config.scope) body.set("scope", config.scope);
    if (config.audience) body.set("audience", config.audience);
    const init: RequestInit = {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString("base64"),
      },
      body: body.toString(),
    };
    const res = await (dpop ? dpop.fetch(doFetch, config.tokenUrl, init) : doFetch(config.tokenUrl, init));
    if (res.status !== 200) throw new Error(`gatekeeper: client credentials: status ${res.status}`);
    const r = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!r.access_token) throw new Error("gatekeeper: client credentials: no access_token");
    cached = { token: r.access_token, until: Date.now() + ((r.expires_in ?? 0) - 60) * 1000 };
    return r.access_token;
  }
  return {
    token(): Promise<string> {
      if (cached && Date.now() < cached.until) return Promise.resolve(cached.token);
      inflight ??= fetchToken().finally(() => { inflight = undefined; });
      return inflight;
    },
    proof(method, url, token) {
      if (!dpop) return Promise.reject(new Error("gatekeeper: proof needs dpopKey"));
      return dpop.proof(method, url, token);
    },
  };
}

export { generateDPoPKey } from "./dpop.js";
export { innerToken, type DecryptionKey } from "./jwe.js";
export { createPushApprover, cryptoKeySigner, generatePushKey, PushError, type PushApprover, type PushApproverConfig, type PushChallenge, type PushSigner } from "./push.js";
