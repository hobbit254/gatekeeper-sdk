// Shared devices and PIN sign-in for till and terminal apps (FR-A45,
// FR-A46, ADR-0144): claim the device with its one-time code, then sign
// staff in with their PIN. Every request is signed by the device's own P-256
// key, over the request's URL and body; the private key never leaves it.
// No Node imports; the signer is pluggable (WebCrypto, Keychain, Keystore).

import type { PushSigner } from "./push.js";

/** Signs with the device's P-256 key: the same shape as a push approver's. */
export type DeviceSigner = PushSigner;

export interface SharedDeviceConfig {
  /** https://auth.example.com/t/<tenant> */
  issuer: string;
  signer: DeviceSigner;
  /** Set by claim; keep it with the key. */
  deviceId?: string;
  fetch?: typeof fetch;
  /** Seconds since the epoch; for tests. */
  now?: () => number;
}

/** A PIN session's access token. There is no refresh token: renew it with the device. */
export interface PinSession {
  access_token: string;
  token_type: string;
  /** Seconds; at most 900. Renew before it runs out, or the session ends after 15 idle minutes. */
  expires_in: number;
  sid: string;
  /** When the session ends, renewed or not. */
  session_expires_at: string;
}

export interface SharedDevice {
  readonly deviceId: string | undefined;
  /** Redeems the code an org admin got when registering this device. */
  claim(code: string): Promise<{ device_id: string; name: string; client_id: string }>;
  pinSignIn(userId: string, pin: string): Promise<PinSession>;
  renewPinSession(sid: string): Promise<PinSession>;
  pinSignOut(sid: string): Promise<void>;
}

/**
 * A refused device request. status 401: the device, its signature or the PIN
 * wasn't accepted (it never says which); 423 with code "pin-locked" (retryAfter
 * seconds) or "pin-held" (an org admin must unlock it); 403 "pin-sign-in-off".
 */
export class DeviceError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly retryAfter?: number) {
    super(message);
    this.name = "DeviceError";
  }
}

const b64url = (b: Uint8Array) => {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const enc = (v: unknown) => b64url(new TextEncoder().encode(JSON.stringify(v)));

function jti(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return b64url(b);
}

/** bh: the base64url SHA-256 of the body the signature covers. */
export async function bodyHash(body: Uint8Array): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
}

/**
 * The device's compact JWS over a request to url with body: kid the device
 * id (none on a claim), aud the URL, iat now, a fresh jti and bh.
 */
export async function signDeviceRequest(signer: DeviceSigner, url: string, body: Uint8Array, deviceId?: string, now = () => Math.floor(Date.now() / 1000)): Promise<string> {
  const header: Record<string, string> = { alg: "ES256", typ: "JWT" };
  if (deviceId) header.kid = deviceId;
  const input = `${enc(header)}.${enc({ aud: url, iat: now(), jti: jti(), bh: await bodyHash(body) })}`;
  return `${input}.${b64url(await signer.sign(new TextEncoder().encode(input)))}`;
}

/** The client for one shared device. */
export function createSharedDevice(config: SharedDeviceConfig): SharedDevice {
  const issuer = config.issuer.replace(/\/$/, "");
  const doFetch = config.fetch ?? fetch;
  let deviceId = config.deviceId;

  async function post<T>(path: string, payload: unknown, kid: string | undefined): Promise<T> {
    const url = `${issuer}/v1/devices/${path}`;
    const body = new TextEncoder().encode(JSON.stringify(payload));
    const jws = await signDeviceRequest(config.signer, url, body, kid, config.now);
    const res = await doFetch(url, { method: "POST", body, headers: { "Content-Type": "application/json", Authorization: `Device ${jws}` } });
    if (res.status === 204) return undefined as T;
    const out = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const code = String(out.type ?? "").replace(/^\/errors\//, "");
      const retry = Number(res.headers.get("Retry-After") ?? "") || undefined;
      throw new DeviceError(res.status, code, String(out.detail ?? out.title ?? `status ${res.status}`), retry);
    }
    return out as T;
  }
  const needId = () => {
    if (!deviceId) throw new DeviceError(0, "not-claimed", "claim the device first");
    return deviceId;
  };

  return {
    get deviceId() { return deviceId; },
    async claim(code) {
      const out = await post<{ device_id: string; name: string; client_id: string }>("claim",
        { code, public_jwk: await config.signer.publicJWK() }, undefined);
      deviceId = out.device_id;
      return out;
    },
    pinSignIn: async (userId, pin) => post<PinSession>("pin-sign-in", { user_id: userId, pin }, needId()),
    renewPinSession: async (sid) => post<PinSession>("pin-sessions/renew", { sid }, needId()),
    pinSignOut: async (sid) => post<void>("pin-sign-out", { sid }, needId()),
  };
}
