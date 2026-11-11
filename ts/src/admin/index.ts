// Typed Gatekeeper admin API client (FR-D13, ADR-0088). schema.ts is
// generated from sdk/admin-openapi.json: regenerate with `make sdk-clients`.
import createClient, { type Client, type Middleware } from "openapi-fetch";
import type { paths } from "./schema.js";

export type { components, operations, paths } from "./schema.js";
export type AdminClient = Client<paths>;

export interface AdminClientConfig {
  /** The tenant issuer, e.g. https://auth.example.com/t/acme. */
  issuer: string;
  /** A tenant admin's access token, or a service account's client-credentials token. */
  token: () => Promise<string> | string;
  fetch?: typeof fetch;
}

/** createAdminClient returns a typed client; every request carries the token as a bearer. */
export function createAdminClient(config: AdminClientConfig): AdminClient {
  const client = createClient<paths>({ baseUrl: config.issuer.replace(/\/$/, ""), fetch: config.fetch });
  const bearer: Middleware = {
    async onRequest({ request }) {
      request.headers.set("Authorization", `Bearer ${await config.token()}`);
      return request;
    },
  };
  client.use(bearer);
  return client;
}
