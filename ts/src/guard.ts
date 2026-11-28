// Route guard coverage (FR-S20, ADR-0149): the guards carry a mark, and
// assertEveryRouteGuarded reads an Express app's routes for one, without
// calling any handler.

/** What a route's guard requires. */
export interface Guard {
  kind: "permission" | "resource" | "step-up" | "public" | "signed-in";
  permission?: string;
}

const GUARD = Symbol.for("gatekeeper.guard");

type Fn = (...args: never[]) => unknown;

/** Marks fn as a guard; returns fn. */
export function markGuard<T extends Fn>(guard: Guard, fn: T): T {
  Object.defineProperty(fn, GUARD, { value: guard, enumerable: false });
  return fn;
}

/** The guard a handler carries, if any. */
export function guardOf(fn: unknown): Guard | undefined {
  return typeof fn === "function" ? (fn as unknown as Record<symbol, Guard | undefined>)[GUARD] : undefined;
}

type Next = (err?: unknown) => void;
type AnyReq = { gatekeeper?: unknown };
type AnyRes = { status(code: number): { end(body?: string): unknown }; setHeader(name: string, value: string): unknown };

/** Marks a route as deliberately open; it changes nothing at run time. */
export function publicRoute(): (req: AnyReq, res: AnyRes, next: Next) => void {
  return markGuard({ kind: "public" }, (_req: AnyReq, _res: AnyRes, next: Next) => next());
}

/** Marks a route that any valid token may call; 401 without the Principal express() stores. */
export function signedIn(): (req: AnyReq, res: AnyRes, next: Next) => void {
  return markGuard({ kind: "signed-in" }, (req: AnyReq, res: AnyRes, next: Next) => {
    if (!req.gatekeeper) {
      res.setHeader("WWW-Authenticate", "Bearer");
      res.status(401).end("unauthorized");
      return;
    }
    next();
  });
}

/** Options for the check. */
export interface RouteCheckOptions {
  /** The manifest's keys; those no route guards are listed as unused. */
  permissions?: string[];
  /** Throw when a permission is unused too. */
  failOnUnused?: boolean;
  /** Routes to skip: "GET /health" or "/health". */
  ignore?: string[];
}

/** What the check found. */
export interface RouteReport {
  unguarded: string[];
  unused: string[];
}

interface Layer {
  name?: string;
  handle?: unknown;
  route?: { path: string | string[]; methods?: Record<string, boolean>; stack?: Layer[] };
  path?: string;
  regexp?: RegExp & { fast_slash?: boolean };
}

/** A mounted router's prefix, as far as Express exposes it. */
function mountPath(l: Layer): string {
  if (typeof l.path === "string") return l.path === "/" ? "" : l.path; // Express 5 keeps it
  const src = l.regexp?.source ?? "";
  if (l.regexp?.fast_slash || src === "^\\/?(?=\\/|$)") return "";
  const m = /^\^((?:\\\/[^\\?(]+)+)\\\/\?\(\?=\\\/\|\$\)$/.exec(src); // Express 4: ^\/api\/?(?=\/|$)
  return m ? m[1].replace(/\\\//g, "/") : "";
}

function walk(stack: Layer[], prefix: string, inherited: Guard | undefined, found: { name: string; guard?: Guard }[]): void {
  let mark = inherited;
  for (const l of stack) {
    if (l.route) {
      const methods = Object.keys(l.route.methods ?? {}).filter((m) => l.route!.methods![m] && m !== "_all").map((m) => m.toUpperCase());
      const paths = Array.isArray(l.route.path) ? l.route.path : [l.route.path];
      const guard = (l.route.stack ?? []).map((s) => guardOf(s.handle)).find(Boolean) ?? mark;
      for (const p of paths) for (const m of methods.length ? methods : ["ALL"]) found.push({ name: `${m} ${prefix}${p}`, guard });
      continue;
    }
    const nested = (l.handle as { stack?: Layer[] } | undefined)?.stack;
    if (Array.isArray(nested)) {
      walk(nested, prefix + mountPath(l), mark, found);
      continue;
    }
    mark = guardOf(l.handle) ?? mark; // app.use(publicRoute()) covers the routes after it
  }
}

/** Reports an Express 4 or 5 app's routes with no guard, and unused permissions. */
export function checkRoutes(app: unknown, opts: RouteCheckOptions = {}): RouteReport {
  const a = app as { _router?: { stack?: Layer[] }; router?: { stack?: Layer[] } };
  const stack = a._router?.stack ?? a.router?.stack;
  if (!Array.isArray(stack)) throw new Error("gatekeeper: not an Express app with routes (Express 4 or 5)");
  const found: { name: string; guard?: Guard }[] = [];
  walk(stack, "", undefined, found);
  const ignore = new Set(opts.ignore ?? []);
  const used = new Set<string>();
  const unguarded: string[] = [];
  for (const r of found) {
    const path = r.name.slice(r.name.indexOf(" ") + 1);
    if (ignore.has(r.name) || ignore.has(path)) continue;
    if (!r.guard) unguarded.push(r.name);
    else if (r.guard.permission) used.add(r.guard.permission);
  }
  return { unguarded: [...new Set(unguarded)].sort(), unused: (opts.permissions ?? []).filter((p) => !used.has(p)).sort() };
}

/**
 * Throws, listing them, when an Express app has routes with no Gatekeeper guard
 * (requirePermission, requirePermissionOn, publicRoute or signedIn). Call it in a test.
 */
export function assertEveryRouteGuarded(app: unknown, opts: RouteCheckOptions = {}): RouteReport {
  const rep = checkRoutes(app, opts);
  const problems: string[] = [];
  if (rep.unguarded.length) problems.push(`${rep.unguarded.length} route(s) with no Gatekeeper guard:\n  ${rep.unguarded.join("\n  ")}`);
  if (opts.failOnUnused && rep.unused.length) problems.push(`permission(s) no route guards: ${rep.unused.join(", ")}`);
  if (problems.length) throw new Error(`gatekeeper: ${problems.join("\n")}`);
  return rep;
}

// --- Fastify (ADR-0153) ------------------------------------------------------

/** The slice of a Fastify request the guards use. */
interface FastifyRequestLike {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  url: string;
  protocol?: string;
  gatekeeper?: unknown;
}

/** The slice of a Fastify reply the guards use. */
interface FastifyReplyLike {
  code(status: number): unknown;
  header(name: string, value: string): unknown;
  send(body?: unknown): unknown;
}

type ExpressLike = (req: never, res: never, next: (err?: unknown) => void) => void;

/** A Fastify hook: resolves to continue, or after answering (returning the reply). */
export type FastifyHook = (request: FastifyRequestLike, reply: FastifyReplyLike) => Promise<unknown>;

/** Runs an Express-style guard as a Fastify hook, keeping its mark. */
export function fromExpress(mw: ExpressLike): FastifyHook {
  const hook: FastifyHook = (request, reply) => new Promise((resolve, reject) => {
    const req = { headers: request.headers, method: request.method, url: request.url, originalUrl: request.url,
      protocol: request.protocol, gatekeeper: request.gatekeeper };
    const res = {
      status(code: number) { reply.code(code); return { end: (body?: string) => { reply.send(body ?? ""); resolve(reply); } }; },
      setHeader(name: string, value: string) { reply.header(name, value); },
    };
    (mw as unknown as (q: typeof req, s: typeof res, n: (err?: unknown) => void) => void)(req, res, (err) => {
      if (err) return reject(err);
      request.gatekeeper = req.gatekeeper;
      resolve(undefined);
    });
  });
  const g = guardOf(mw);
  return g ? markGuard(g, hook) : hook;
}

/** Fastify hooks for one Gatekeeper instance: verify on onRequest, the guards on preHandler. */
export interface FastifyGuards {
  verify: FastifyHook;
  requirePermission(permission: string): FastifyHook;
  requirePermissionOn(permission: string, resource: (request: FastifyRequestLike) => string): FastifyHook;
  publicRoute(): FastifyHook;
  signedIn(): FastifyHook;
}

interface RecordedRoute {
  method: string;
  url: string;
  hooks: unknown[];
}

const recorded = new WeakMap<object, RecordedRoute[]>();

/** Starts recording a Fastify app's routes; call it before adding them. */
export function recordFastifyRoutes(app: { addHook(name: "onRoute", fn: (route: Record<string, unknown>) => void): unknown }): void {
  const routes: RecordedRoute[] = [];
  recorded.set(app, routes);
  app.addHook("onRoute", (route) => {
    const hooks = ["onRequest", "preHandler"].flatMap((k) => {
      const h = route[k];
      return Array.isArray(h) ? h : h ? [h] : [];
    });
    const methods = Array.isArray(route.method) ? route.method as string[] : [String(route.method)];
    for (const m of methods) routes.push({ method: m, url: String(route.url), hooks });
  });
}

/** Reports a recorded Fastify app's routes with no guard, and unused permissions. */
export function checkFastifyRoutes(app: object, opts: RouteCheckOptions = {}): RouteReport {
  const routes = recorded.get(app);
  if (!routes) throw new Error("gatekeeper: call recordFastifyRoutes(app) before adding routes");
  const ignore = new Set(opts.ignore ?? []);
  const used = new Set<string>();
  const unguarded = new Set<string>();
  const gets = new Set(routes.filter((r) => r.method === "GET").map((r) => r.url));
  for (const r of routes) {
    if (r.method === "HEAD" && gets.has(r.url)) continue; // the HEAD twin Fastify adds for a GET
    const name = `${r.method} ${r.url}`;
    if (ignore.has(name) || ignore.has(r.url)) continue;
    const g = r.hooks.map(guardOf).find(Boolean);
    if (!g) unguarded.add(name);
    else if (g.permission) used.add(g.permission);
  }
  return { unguarded: [...unguarded].sort(), unused: (opts.permissions ?? []).filter((p) => !used.has(p)).sort() };
}

/**
 * Throws, listing them, when a recorded Fastify app has routes with no Gatekeeper guard
 * in their onRequest or preHandler hooks. A hook added with app.addHook isn't seen.
 */
export function assertEveryFastifyRouteGuarded(app: object, opts: RouteCheckOptions = {}): RouteReport {
  const rep = checkFastifyRoutes(app, opts);
  const problems: string[] = [];
  if (rep.unguarded.length) problems.push(`${rep.unguarded.length} route(s) with no Gatekeeper guard:\n  ${rep.unguarded.join("\n  ")}`);
  if (opts.failOnUnused && rep.unused.length) problems.push(`permission(s) no route guards: ${rep.unused.join(", ")}`);
  if (problems.length) throw new Error(`gatekeeper: ${problems.join("\n")}`);
  return rep;
}
