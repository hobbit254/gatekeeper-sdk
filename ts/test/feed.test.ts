import { describe, expect, it } from "vitest";
import { createRevocationFeed } from "../src/index.js";

// A fake Gatekeeper: a token, a snapshot, and a stream we push lines into.
function fakeServer(snapshot: object, opts: { streamStatus?: number } = {}) {
  let push: (s: string) => void = () => {};
  let close: () => void = () => {};
  const seen: { url: string; lastEventId?: string }[] = [];
  const f = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const h = new Headers(init?.headers);
    seen.push({ url, lastEventId: h.get("last-event-id") ?? undefined });
    if (url.endsWith("/oauth2/token")) return Response.json({ access_token: "t", expires_in: 3600 });
    if (url.endsWith("/v1/revocations")) return Response.json(snapshot);
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        const enc = new TextEncoder();
        push = (s) => c.enqueue(enc.encode(s));
        close = () => c.close();
        init?.signal?.addEventListener("abort", () => { try { c.close(); } catch { /* closed */ } });
      },
    });
    return new Response(body, { status: opts.streamStatus ?? 200 });
  }) as typeof fetch;
  return { f, push: (s: string) => push(s), close: () => close(), seen };
}

const later = () => new Date(Date.now() + 3_600_000).toISOString();
const until = (pred: () => boolean | Promise<boolean>) => expect.poll(pred, { timeout: 2000, interval: 10 }).toBe(true);

describe("revocation feed (FR-S17)", () => {
  it("refuses before the first snapshot, then follows the snapshot and the stream", async () => {
    const s = fakeServer({ items: [{ kind: "sid", value: "s1", until: later() }], cursor: "100-0" });
    const feed = createRevocationFeed({ issuer: "https://gk.test/t/a/", clientId: "c", clientSecret: "x", fetch: s.f });
    await expect(feed.denied("s1", "j")).rejects.toThrow("stale");
    feed.start();
    await until(async () => feed.denied("s1", "j").catch(() => false));
    expect(await feed.denied("s2", "j")).toBe(false);
    await until(() => s.seen.some((x) => x.url.endsWith("/stream")));
    expect(s.seen.find((x) => x.url.endsWith("/stream"))?.lastEventId).toBe("100-0");
    s.push(`id: 101-0\ndata: ${JSON.stringify({ kind: "jti", value: "j9", until: later() })}\n\n`);
    await until(() => feed.denied("", "j9"));
    feed.stop();
  });

  it("ignores lapsed entries and empty ids", async () => {
    const s = fakeServer({ items: [{ kind: "sid", value: "old", until: new Date(Date.now() - 1000).toISOString() }], cursor: "1-0" });
    const feed = createRevocationFeed({ issuer: "https://gk.test/t/a", clientId: "c", clientSecret: "x", fetch: s.f });
    feed.start();
    await until(async () => (await feed.denied("x", "y").catch(() => null)) === false);
    expect(await feed.denied("old", "")).toBe(false);
    feed.stop();
  });

  it("goes stale when the stream is refused", async () => {
    const s = fakeServer({ items: [], cursor: "1-0" }, { streamStatus: 403 });
    const feed = createRevocationFeed({ issuer: "https://gk.test/t/a", clientId: "c", clientSecret: "x", fetch: s.f, maxStaleSec: 10 });
    const real = Date.now;
    feed.start();
    await until(async () => (await feed.denied("a", "b").catch(() => null)) === false);
    Date.now = () => real() + 11_000;
    try {
      await expect(feed.denied("a", "b")).rejects.toThrow("stale");
    } finally {
      Date.now = real;
      feed.stop();
    }
  });
});
