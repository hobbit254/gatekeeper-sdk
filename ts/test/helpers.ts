import { readFileSync } from "node:fs";
import { createGatekeeper } from "../src/index.js";

// The shared contract every SDK must pass (ADR-0038).
const v = JSON.parse(readFileSync(new URL("../../contract/vectors.json", import.meta.url), "utf8"));

/** Serves the JWKS and role map from the vectors file and counts role-map fetches. */
export function fixedFetch(roleMaps: unknown[] = [v.role_map]) {
  const calls = { roleMap: 0 };
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
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

export const sdk = (f: typeof fetch) =>
  createGatekeeper({ issuer: v.issuer, audience: v.audience, clientId: v.client_id, clientSecret: v.client_secret, fetch: f });

export { v };
