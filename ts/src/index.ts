// Gatekeeper TypeScript SDK: verify access tokens offline, hydrate a
// Principal, resolve permissions from the client's role map and guard routes
// (docs/INTEGRATION.md, docs/TOKENS.md, ADR-0005, ADR-0038).
import { createLocalJWKSet, errors, jwtVerify, type JSONWebKeySet, type JWTPayload } from "jose";

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
  /** Express middleware: verifies the bearer token, or answers 401. */
  express(): Middleware;
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

  async function verify(token: string): Promise<Principal> {
    let c: JWTPayload;
    try {
      c = await verifySignature(token);
    } catch (e) {
      throw new InvalidTokenError(e instanceof Error ? e.message : "verification failed");
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
      can: (p: string) => perms.includes(p),
    };
  }

  return {
    verify,
    express(): Middleware {
      return (req, res, next) => {
        const header = req.headers.authorization;
        const raw = typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : "";
        if (!raw) {
          res.setHeader("WWW-Authenticate", "Bearer");
          res.status(401).end("unauthorized");
          return;
        }
        verify(raw).then(
          (p) => { req.gatekeeper = p; next(); },
          (e) => {
            if (!(e instanceof InvalidTokenError)) return next(e); // JWKS or role map unreachable: a 5xx, not a 401
            res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
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
