import { UnsecuredJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { mountSupportBanner, supportSession, type SupportSession } from "../src/browser.js";

// The support-session banner for product UIs (FR-M5, ADR-0159).

const ends = new Date("2026-11-28T10:48:00Z");
const at = (act?: Record<string, unknown>) => new UnsecuredJWT({ sub: "u1", ...(act ? { act } : {}) }).encode();

describe("supportSession: what the token says, for display only", () => {
  it("is null for an ordinary token, or one that isn't a JWT", () => {
    expect(supportSession(at())).toBeNull();
    expect(supportSession("at-1")).toBeNull();
    expect(supportSession(at({ ends_at: 1 }))).toBeNull(); // no actor
  });
  it("reads the actor, the mode and the end", () => {
    const s = supportSession(at({ sub: "admin-1", ends_at: ends.getTime() / 1000, mode: "write" }));
    expect(s).toEqual({ actor: "admin-1", mode: "write", readOnly: false, endsAt: ends });
  });
  it("counts a token without a mode as read-only, as the server does", () => {
    const s = supportSession(at({ sub: "admin-1", ends_at: ends.getTime() / 1000 }));
    expect(s?.mode).toBe("read");
    expect(s?.readOnly).toBe(true);
  });
});

/** Just enough DOM for the banner. */
class El {
  children: El[] = [];
  parent: El | null = null;
  attrs: Record<string, string> = {};
  style: Record<string, string> = {};
  textContent = "";
  hidden = false;
  listeners: Record<string, (() => void)[]> = {};
  constructor(public tagName: string) {}
  setAttribute(k: string, v: string) { this.attrs[k] = v; }
  appendChild(c: El) { c.parent = this; this.children.push(c); return c; }
  prepend(c: El) { c.parent = this; this.children.unshift(c); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((x) => x !== this); this.parent = null; }
  addEventListener(t: string, f: () => void) { (this.listeners[t] ??= []).push(f); }
  click() { for (const f of this.listeners.click ?? []) f(); }
  text(): string { return this.textContent + this.children.filter((c) => !c.hidden).map((c) => c.text()).join(""); }
  find(tag: string): El | undefined { return this.children.find((c) => c.tagName === tag) ?? this.children.map((c) => c.find(tag)).find(Boolean); }
}
const fakeDocument = () => { const body = new El("body"); body.appendChild(new El("main")); return { body, createElement: (t: string) => new El(t) }; };

function mount(over: Partial<Parameters<typeof mountSupportBanner>[0]> = {}, session?: SupportSession) {
  const doc = fakeDocument();
  let clock = new Date("2026-11-28T10:00:00Z").getTime();
  let tick: () => void = () => {};
  const clear = vi.fn();
  const s = session ?? { actor: "admin-1", mode: "read" as const, readOnly: true, endsAt: ends };
  const unmount = mountSupportBanner({ session: s, document: doc as unknown as Document, now: () => clock,
    setInterval: (f: () => void) => { tick = f; return 7; }, clearInterval: clear, ...over });
  return { doc, banner: doc.body.children[0], unmount, clear, advance: (ms: number) => { clock += ms; tick(); } };
}

describe("mountSupportBanner (FR-M5)", () => {
  it("sits first on the page and says who, how and until when", () => {
    const { doc, banner } = mount({ name: "Wanjiru" });
    expect(doc.body.children).toHaveLength(2);
    expect(banner.attrs.role).toBe("status");
    expect(banner.text()).toContain("Support session · Viewing as Wanjiru · Read-only · Ends in 48 min");
    expect(banner.find("button")?.textContent).toBe("Stop");
  });

  it("says when the session can change things", () => {
    const { banner } = mount({}, { actor: "a", mode: "write", readOnly: false, endsAt: ends });
    expect(banner.text()).toContain("Support session · Can change things · Ends in 48 min");
  });

  it("Stop calls the app", () => {
    const onStop = vi.fn();
    mount({ onStop }).banner.find("button")?.click();
    expect(onStop).toHaveBeenCalledOnce();
  });

  it("counts down, then says it ended, once", () => {
    const onEnded = vi.fn();
    const { banner, advance, clear } = mount({ onEnded });
    advance(30 * 60_000);
    expect(banner.text()).toContain("Ends in 18 min");
    advance(18 * 60_000 - 20_000);
    expect(banner.text()).toContain("Ends in 1 min"); // never "0 min" while time is left
    advance(20_000);
    expect(banner.text()).toContain("Support session ended");
    expect(banner.find("button")?.hidden).toBe(true);
    advance(60_000);
    expect(onEnded).toHaveBeenCalledOnce();
    expect(clear).toHaveBeenCalledWith(7);
  });

  it("takes other words", () => {
    const { banner } = mount({ name: "Wanjiru", labels: { title: "Kipindi cha msaada", viewingAs: "Unaona kama {name}", readOnly: "Kusoma tu",
      endsIn: "Kinaisha baada ya dakika {minutes}", stop: "Simamisha" } });
    expect(banner.text()).toContain("Kipindi cha msaada · Unaona kama Wanjiru · Kusoma tu · Kinaisha baada ya dakika 48");
    expect(banner.find("button")?.textContent).toBe("Simamisha");
  });

  it("goes away when unmounted", () => {
    const { doc, unmount, clear } = mount();
    unmount();
    expect(doc.body.children.map((c) => c.tagName)).toEqual(["main"]);
    expect(clear).toHaveBeenCalledWith(7);
  });
});
