// Drives the example against a real Gatekeeper and the Go example API
// (FR-T9, ADR-0130). tests/feature/sdk sets GK_LIVE_*; without them it skips.
// The hosted sign-in page is completed over plain HTTP, as harness.Browser does in Go.
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app";

const env = process.env;
const live = !!env.GK_LIVE_ISSUER && !!env.GK_LIVE_API;

class MemoryStorage {
  private m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

/** Signs in on the hosted page at url with a password and returns where it sends the browser back to. */
async function hostedSignIn(url: string, email: string, password: string, origin: string): Promise<string> {
  const jar = new Map<string, string>();
  const ip = `10.47.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`; // the harness trusts X-Forwarded-For
  const headers = (extra: Record<string, string> = {}) => ({ cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "), "x-forwarded-for": ip, ...extra });
  const keep = (res: Response) => {
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const i = kv.indexOf("=");
      jar.set(kv.slice(0, i), kv.slice(i + 1));
    }
  };
  let res = await fetch(url, { headers: headers(), redirect: "manual" });
  keep(res);
  const csrf = /name="csrf" value="([^"]+)"/.exec(await res.text())?.[1];
  expect(csrf, "the sign-in page").toBeDefined();
  res = await fetch(url, { method: "POST", redirect: "manual", body: new URLSearchParams({ identifier: email, password, csrf: csrf! }),
    headers: headers({ "content-type": "application/x-www-form-urlencoded", origin }) });
  expect(res.status, await res.clone().text()).toBe(303);
  return res.headers.get("location")!;
}

describe.skipIf(!live)("the example app against a real tenant", () => {
  it("signs in, calls the API, and is refused without the permission or a token", async () => {
    let went = "";
    const app = createApp({ issuer: env.GK_LIVE_ISSUER!, clientId: env.GK_LIVE_CLIENT!, redirectUri: env.GK_LIVE_REDIRECT!,
      apiUrl: env.GK_LIVE_API!, navigate: (u) => { went = u; }, storage: new MemoryStorage() });

    await app.signIn();
    expect(went).toContain("/oauth2/authorize?");
    const back = await hostedSignIn(went, env.GK_LIVE_EMAIL!, env.GK_LIVE_PASSWORD!, env.GK_LIVE_ORIGIN!);
    expect(back.startsWith(env.GK_LIVE_REDIRECT!)).toBe(true);
    const user = await app.finishSignIn(back);
    expect(user.sub).toBeTruthy();

    const me = await app.callApi("/api/me");
    expect(me.status, me.body).toBe(200);
    expect(JSON.parse(me.body).sub).toBe(user.sub);
    expect((await app.callApi("/api/reports")).status, "no role grants report:read").toBe(403);
    expect((await fetch(env.GK_LIVE_API + "/api/me")).status, "no token").toBe(401);
  });
});
