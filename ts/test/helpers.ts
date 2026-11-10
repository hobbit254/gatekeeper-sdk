import { readFileSync } from "node:fs";
import { createGatekeeper } from "../src/index.js";

// The shared contract every SDK must pass (ADR-0038).
const v = JSON.parse(readFileSync(new URL("../../contract/vectors.json", import.meta.url), "utf8"));

/** Serves the JWKS and role map from the vectors file and counts role-map fetches. */
export function fixedFetch(roleMaps: unknown[] = [v.role_map]) {
  const calls = { roleMap: 0, introspect: 0 };
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === `${v.issuer}/oauth2/introspect` && init?.method === "POST") {
      calls.introspect++;
      const auth = new Headers(init.headers).get("authorization");
      if (auth !== "Basic " + Buffer.from(`${v.client_id}:${v.client_secret}`).toString("base64")) {
        return Response.json({ error: "invalid_client" }, { status: 401 });
      }
      const token = new URLSearchParams(String(init.body)).get("token") ?? "";
      return Response.json(v.api_keys.introspection[token] ?? { active: false });
    }
    if (url === `${v.issuer}/.well-known/jwks.json`) return Response.json(v.jwks);
    if (url === `${v.issuer}/v1/clients/${v.client_id}/role-map`) {
      const auth = new Headers(init?.headers).get("authorization");
      if (auth !== "Basic " + Buffer.from(`${v.client_id}:${v.client_secret}`).toString("base64")) {
        return new Response("{}", { status: 401 });
      }
      return Response.json(roleMaps[Math.min(calls.roleMap++, roleMaps.length - 1)]);
    }
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  return { f, calls };
}

export const sdk = (f: typeof fetch, denylist?: (sid: string, jti: string) => Promise<boolean>) =>
  createGatekeeper({ issuer: v.issuer, audience: v.audience, clientId: v.client_id, clientSecret: v.client_secret, fetch: f, denylist });

export { v };
