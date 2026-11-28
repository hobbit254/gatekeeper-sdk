// The support-session banner for product UIs (FR-M5, ADR-0159). A support
// session's access token carries act {sub, ends_at, mode}; the page reads it
// for display only (the API verifies the token) and shows a banner saying so.
// No Node imports: this runs in browsers.
import { decodeJwt } from "jose";

/** A support session, as the access token describes it. */
export interface SupportSession {
  /** The admin acting as the user. */
  actor: string;
  /** "read" unless writing was allowed (ADR-0146). */
  mode: "read" | "write";
  readOnly: boolean;
  endsAt: Date;
}

/** The support session accessToken is part of, or null; decoded, not verified: for display only. */
export function supportSession(accessToken: string): SupportSession | null {
  let act: unknown;
  try {
    act = decodeJwt(accessToken).act;
  } catch {
    return null;
  }
  if (!act || typeof act !== "object") return null;
  const a = act as { sub?: unknown; ends_at?: unknown; mode?: unknown };
  if (typeof a.sub !== "string" || !a.sub) return null;
  const mode = a.mode === "write" ? "write" : "read"; // no mode is read, as on the server
  return { actor: a.sub, mode, readOnly: mode === "read", endsAt: new Date((typeof a.ends_at === "number" ? a.ends_at : 0) * 1000) };
}

/** The banner's words; {name} and {minutes} are filled in. */
export interface SupportBannerLabels {
  title: string;
  viewingAs: string;
  readOnly: string;
  canChange: string;
  endsIn: string;
  ended: string;
  stop: string;
}

const english: SupportBannerLabels = {
  title: "Support session", viewingAs: "Viewing as {name}", readOnly: "Read-only", canChange: "Can change things",
  endsIn: "Ends in {minutes} min", ended: "Support session ended", stop: "Stop",
};

export interface SupportBannerOptions {
  session: SupportSession;
  /** Whose account is being viewed, as the product names them. */
  name?: string;
  /** Stop pressed; the product signs out, or ends the session from its support tool. */
  onStop?: () => void;
  /** Called once when the session's time is up. */
  onEnded?: () => void;
  /** Where the banner goes, first; default document.body. */
  container?: HTMLElement;
  labels?: Partial<SupportBannerLabels>;
  document?: Document;
  now?: () => number;
  setInterval?: (f: () => void, ms: number) => unknown;
  clearInterval?: (id: unknown) => void;
}

/**
 * Puts a banner first in the page while a support session lasts: who is being
 * viewed, whether the session can change things, the minutes left, and Stop.
 * Returns a function that removes it.
 */
export function mountSupportBanner(opts: SupportBannerOptions): () => void {
  const doc = opts.document ?? globalThis.document;
  const words = { ...english, ...opts.labels };
  const now = opts.now ?? (() => Date.now());
  const every = opts.setInterval ?? ((f: () => void, ms: number) => globalThis.setInterval(f, ms));
  const stopTimer = opts.clearInterval ?? ((id: unknown) => globalThis.clearInterval(id as ReturnType<typeof setInterval>));
  const s = opts.session;

  const banner = doc.createElement("div");
  banner.setAttribute("role", "status");
  banner.setAttribute("data-gatekeeper-support", s.mode);
  Object.assign(banner.style, { background: "#b42318", color: "#fff", padding: "8px 16px", font: "600 14px/1.4 system-ui, sans-serif",
    display: "flex", gap: "12px", alignItems: "center", justifyContent: "center", position: "sticky", top: "0", zIndex: "2147483647" });
  const text = doc.createElement("span");
  const stop = doc.createElement("button");
  stop.setAttribute("type", "button");
  stop.textContent = words.stop;
  Object.assign(stop.style, { background: "#fff", color: "#b42318", border: "0", borderRadius: "999px", padding: "2px 12px", font: "inherit", cursor: "pointer" });
  stop.addEventListener("click", () => opts.onStop?.());
  banner.appendChild(text);
  banner.appendChild(stop);
  (opts.container ?? doc.body).prepend(banner);

  let ended = false;
  let timer: unknown;
  const render = () => {
    const left = s.endsAt.getTime() - now();
    if (left <= 0) {
      text.textContent = words.ended;
      stop.hidden = true;
      if (!ended) {
        ended = true;
        stopTimer(timer);
        opts.onEnded?.();
      }
      return;
    }
    const parts = [words.title];
    if (opts.name) parts.push(words.viewingAs.replace("{name}", opts.name));
    parts.push(s.readOnly ? words.readOnly : words.canChange);
    parts.push(words.endsIn.replace("{minutes}", String(Math.ceil(left / 60_000))));
    text.textContent = parts.join(" · ");
  };
  timer = every(render, 30_000);
  render();
  return () => {
    stopTimer(timer);
    banner.remove();
  };
}
