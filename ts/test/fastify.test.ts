import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { assertEveryFastifyRouteGuarded, checkFastifyRoutes, createGatekeeper, recordFastifyRoutes } from "../src/index.js";

// FR-S20 (ADR-0153): a real Fastify app's routes without a guard are listed;
// the guards still answer 401 and 403 and keep the handler from running.

const gk = createGatekeeper({ issuer: "https://auth.test/t/acme", audience: "api", clientId: "web",
  fetch: (async () => new Response("{}", { status: 404 })) as typeof fetch });
const guards = gk.fastify();

function app() {
  const f = Fastify();
  recordFastifyRoutes(f);
  f.get("/orders", { onRequest: guards.verify, preHandler: guards.requirePermission("order:read") }, async () => "orders");
  f.post("/orders/:id/refund", { onRequest: guards.verify, preHandler: [guards.requirePermissionOn("order:refund", (r) => `order:${r.url}`)] }, async () => "ok");
  f.get("/health", { preHandler: guards.publicRoute() }, async () => "ok");
  f.get("/me", { onRequest: guards.verify, preHandler: guards.signedIn() }, async () => "me");
  return f;
}

describe("Fastify route guard coverage", () => {
  it("lists unguarded routes and unused permissions", async () => {
    const f = app();
    let ran = false;
    f.post("/orders", { onRequest: guards.verify }, async () => { ran = true; return "made"; });
    await f.ready();
    const rep = checkFastifyRoutes(f, { permissions: ["order:read", "order:refund", "order:export"] });
    expect(rep.unguarded).toEqual(["POST /orders"]);
    expect(rep.unused).toEqual(["order:export"]);
    expect(() => assertEveryFastifyRouteGuarded(f)).toThrow(/POST \/orders/);
    expect(assertEveryFastifyRouteGuarded(f, { ignore: ["POST /orders"] }).unguarded).toEqual([]);
    expect(() => assertEveryFastifyRouteGuarded(f, { ignore: ["/orders"], permissions: ["order:export"], failOnUnused: true })).toThrow(/order:export/);
    expect(ran).toBe(false);
    await f.close();
  });

  it("guards still refuse", async () => {
    const f = app();
    await f.ready();
    const noToken = await f.inject({ method: "GET", url: "/orders" });
    expect(noToken.statusCode).toBe(401);
    expect(noToken.headers["www-authenticate"]).toBe("Bearer");
    const open = await f.inject({ method: "GET", url: "/health" });
    expect(open.statusCode).toBe(200);
    await f.close();
    const bare = Fastify();
    bare.get("/orders", { preHandler: guards.requirePermission("order:read") }, async () => "orders");
    bare.get("/me", { preHandler: guards.signedIn() }, async () => "me");
    expect((await bare.inject({ method: "GET", url: "/orders" })).statusCode).toBe(403);
    expect((await bare.inject({ method: "GET", url: "/me" })).statusCode).toBe(401);
    await bare.close();
  });

  it("needs recording first", () => {
    expect(() => checkFastifyRoutes(Fastify())).toThrow(/recordFastifyRoutes/);
  });
});
