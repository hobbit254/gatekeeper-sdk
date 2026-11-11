import { describe, expect, it } from "vitest";
import { createAdminClient } from "../src/admin/index.js";

describe("admin client (ADR-0088)", () => {
  it("calls the tenant issuer with the bearer token and typed bodies", async () => {
    const seen: Request[] = [];
    const client = createAdminClient({
      issuer: "https://auth.test/t/acme/",
      token: async () => "tok",
      fetch: async (input) => {
        seen.push(input as Request);
        return Response.json({ id: "u1", status: "active" });
      },
    });
    const { data, error } = await client.POST("/v1/admin/users/{id}/suspend", { params: { path: { id: "u1" } } });
    expect(error).toBeUndefined();
    expect(data).toBeDefined();
    expect(seen[0].url).toBe("https://auth.test/t/acme/v1/admin/users/u1/suspend");
    expect(seen[0].headers.get("Authorization")).toBe("Bearer tok");
  });
});
