import { describe, expect, it } from "vitest";
import { assertEveryRouteGuarded, checkRoutes, createGatekeeper, guardOf, publicRoute, requirePermission, signedIn } from "../src/index.js";

// FR-S20 (ADR-0149): routes without a guard are listed, through nested
// routers in Express 4 and 5 shapes, without calling any handler.

const handler = () => { throw new Error("never called"); };
const route = (method: string, path: string, ...stack: unknown[]) =>
  ({ route: { path, methods: { [method]: true }, stack: stack.map((h) => ({ handle: h })) } });

describe("route guard coverage", () => {
  const gk = createGatekeeper({ issuer: "https://auth.test/t/acme", audience: "api", clientId: "web", fetch: (async () => new Response("{}")) as typeof fetch });
  const auth = gk.express();

  it("finds guards in an Express 4 app, nested routers included", () => {
    const api = { stack: [
      route("get", "/orders", auth, requirePermission("order:read"), handler),
      route("post", "/orders/:id/refund", auth, gk.requirePermissionOn("order:refund", () => "order:1"), handler),
      route("post", "/orders", auth, handler),
    ] };
    const app = { _router: { stack: [
      { name: "query", handle: () => undefined },
      route("get", "/health", publicRoute(), handler),
      route("get", "/me", auth, signedIn(), handler),
      { name: "router", handle: api, regexp: Object.assign(/^\/api\/?(?=\/|$)/i, { fast_slash: false }) },
    ] } };
    const rep = checkRoutes(app, { permissions: ["order:read", "order:refund", "order:export"] });
    expect(rep.unguarded).toEqual(["POST /api/orders"]);
    expect(rep.unused).toEqual(["order:export"]);
    expect(() => assertEveryRouteGuarded(app)).toThrow(/POST \/api\/orders/);
    expect(assertEveryRouteGuarded(app, { ignore: ["POST /api/orders"] }).unguarded).toEqual([]);
    expect(() => assertEveryRouteGuarded(app, { ignore: ["/api/orders"], permissions: ["order:export"], failOnUnused: true })).toThrow(/order:export/);
  });

  it("reads Express 5's router and app-level marks", () => {
    const app = { router: { stack: [
      { name: "public", handle: publicRoute() }, // app.use(publicRoute()) covers what follows
      route("get", "/docs", handler),
      { name: "router", path: "/v1", handle: { stack: [route("delete", "/things/:id", handler)] } },
    ] } };
    expect(checkRoutes(app).unguarded).toEqual([]);
    expect(checkRoutes({ router: { stack: [route("delete", "/things/:id", handler)] } }).unguarded).toEqual(["DELETE /things/:id"]);
    expect(() => checkRoutes({})).toThrow(/not an Express app/);
  });

  it("marks guards and keeps them working", () => {
    expect(guardOf(requirePermission("a:b"))).toEqual({ kind: "permission", permission: "a:b" });
    expect(guardOf(publicRoute())).toEqual({ kind: "public" });
    expect(guardOf(handler)).toBeUndefined();
    let code = 0;
    signedIn()({}, { status: (c: number) => { code = c; return { end: () => undefined }; }, setHeader: () => undefined }, () => { code = 200; });
    expect(code).toBe(401);
  });
});
