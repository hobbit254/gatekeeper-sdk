// Gatekeeper TypeScript SDK: verify access tokens offline, hydrate a
// Principal, resolve permissions from the client's role map and guard routes
// (docs/INTEGRATION.md, docs/TOKENS.md, ADR-0005, ADR-0038).
import { createHash } from "node:crypto";
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
  /** Exact key match; wildcards are already expanded in the role map. */
  can(permission: string): boolean;
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

export interface Gatekeeper {
  /** Runs the TOKENS.md checklist and returns the Principal. */
  verify(token: string): Promise<Principal>;
  /** Checks a request's DPoP proof for a DPoP-bound principal (RFC 9449, ADR-0070). */
  verifyDPoP(p: Principal, accessToken: string, proof: string, method: string, url: string): Promise<void>;
  /** Express middleware: verifies the token ("Bearer", or "DPoP" with a proof), or answers 401. */
  express(): Middleware;
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

  async function permissions(roles: string[], rv: number): Promise<string[]> {
    if (!roleMap || rv > roleMap.rv) {
      // Single-flight: concurrent requests share one refetch.
      roleMapInflight ??= getJSON<RoleMap>(`${issuer}/v1/clients/${encodeURIComponent(config.clientId)}/role-map`, true)
        .finally(() => { roleMapInflight = undefined; });
      roleMap = await roleMapInflight;
    }
    const out = new Set<string>();
    for (const r of roles) for (const p of roleMap.roles[r] ?? []) out.add(p);
    return [...out];
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
    const perms = await permissions(roles, rv);
    return {
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
      can: (p: string) => perms.includes(p),
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

  return {
    verify,
    verifyDPoP,
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

/** Answers 403 unless the request's Principal holds permission. Sensitive
 * permissions and direct grants need /v1/authz/check (ADR-0005). */
export function requirePermission(permission: string): Middleware {
  return (req, res, next) => {
    if (!req.gatekeeper?.can(permission)) {
      res.status(403).end("forbidden");
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
}

/** Returns a token source: `token()` resolves a token valid for at least another minute; concurrent calls share one request. */
export function createClientCredentials(config: ClientCredentialsConfig): { token(): Promise<string> } {
  const doFetch = config.fetch ?? fetch;
  let cached: { token: string; until: number } | undefined;
  let inflight: Promise<string> | undefined;
  async function fetchToken(): Promise<string> {
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    if (config.scope) body.set("scope", config.scope);
    if (config.audience) body.set("audience", config.audience);
    const res = await doFetch(config.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString("base64"),
      },
      body: body.toString(),
    });
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
  };
}
