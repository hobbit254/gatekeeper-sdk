import { createClientCredentials } from "./index.js";

// The revocation feed (FR-S17, ADR-0123), for APIs that can't reach Gatekeeper's
// Redis: pass feed.denied as the denylist option.

export interface RevocationFeedConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  fetch?: typeof fetch;
  /** Seconds without news before every token is refused (default 60, 10 to 300). */
  maxStaleSec?: number;
}

export interface RevocationFeed {
  /** The denylist: true refuses the token; it throws (refusing too) while the feed is stale. */
  denied(sid: string, jti: string): Promise<boolean>;
  /** Snapshot, then stream, reconnecting with backoff until stop(). */
  start(): void;
  stop(): void;
}

interface Revocation { kind: string; value: string; until: string }

export function createRevocationFeed(config: RevocationFeedConfig): RevocationFeed {
  const f = config.fetch ?? fetch;
  const issuer = config.issuer.replace(/\/+$/, "");
  const maxStale = Math.min(300, Math.max(10, config.maxStaleSec ?? 60)) * 1000;
  const cc = createClientCredentials({ tokenUrl: `${issuer}/oauth2/token`, clientId: config.clientId, clientSecret: config.clientSecret, scope: "revocations:read", fetch: f });
  let denied = new Map<string, number>(); // "sid:"+id or "jti:"+id -> until (ms)
  let cursor = "";
  let heard = 0;
  let abort: AbortController | undefined;
  const add = (r: Revocation) => denied.set(`${r.kind}:${r.value}`, Date.parse(r.until));

  async function snapshot(tok: string, signal: AbortSignal) {
    const res = await f(`${issuer}/v1/revocations`, { headers: { authorization: `Bearer ${tok}` }, signal });
    if (res.status !== 200) throw new Error(`revocations snapshot: status ${res.status}`);
    const snap = (await res.json()) as { items: Revocation[]; cursor: string };
    denied = new Map();
    snap.items.forEach(add);
    cursor = snap.cursor;
    heard = Date.now();
  }

  async function listen(tok: string, signal: AbortSignal) {
    const res = await f(`${issuer}/v1/revocations/stream`, {
      headers: { authorization: `Bearer ${tok}`, accept: "text/event-stream", "last-event-id": cursor }, signal,
    });
    if (res.status !== 200 || !res.body) throw new Error(`revocations stream: status ${res.status}`);
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = "";
    let id = "", event = "", data = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buf += value;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).replace(/\r$/, "");
        buf = buf.slice(nl + 1);
        heard = Date.now(); // pings and events alike: the feed is alive
        if (line === "") {
          if (event === "reset") { cursor = ""; return; } // the server lost our place: snapshot again
          if (data) {
            try { add(JSON.parse(data) as Revocation); if (id) cursor = id; } catch { /* a malformed event is skipped */ }
          }
          id = event = data = "";
        } else if (line.startsWith("id: ")) id = line.slice(4);
        else if (line.startsWith("event: ")) event = line.slice(7);
        else if (line.startsWith("data: ")) data = line.slice(6);
      }
    }
  }

  async function run(signal: AbortSignal) {
    let backoff = 1000;
    while (!signal.aborted) {
      try {
        const tok = await cc.token();
        if (!cursor) await snapshot(tok, signal);
        await listen(tok, signal);
        backoff = 1000; // a clean close after the server's 10 minutes
        continue;
      } catch {
        if (signal.aborted) return;
      }
      await new Promise((r) => setTimeout(r, backoff / 2 + Math.random() * (backoff / 2)));
      backoff = Math.min(backoff * 2, 30_000);
    }
  }

  return {
    async denied(sid, jti) {
      const now = Date.now();
      if (!heard || now - heard > maxStale) throw new Error("the revocation feed is stale");
      return [`sid:${sid}`, `jti:${jti}`].some((k) => !k.endsWith(":") && (denied.get(k) ?? 0) > now);
    },
    start() {
      if (abort) return;
      abort = new AbortController();
      void run(abort.signal);
    },
    stop() {
      abort?.abort();
      abort = undefined;
    },
  };
}
