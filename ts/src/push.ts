// Push login approval for apps (FR-A27, ADR-0111): enrol the phone as an
// approver, list pending sign-ins and approve with the number the user picks.
// No Node imports; the signer is pluggable so the key can live in the
// platform keystore (iOS Keychain, Android Keystore) or WebCrypto.

/** Signs with the approver's P-256 key. */
export interface PushSigner {
  /** The public key as a JWK ({kty: "EC", crv: "P-256", x, y}). */
  publicJWK(): Promise<JsonWebKey>;
  /** An ES256 signature over data: 64 bytes, r then s (IEEE P1363, as WebCrypto returns). */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** A pending sign-in, as the phone shows it. */
export interface PushChallenge {
  id: string;
  client_id: string;
  client_name?: string;
  device: string;
  country?: string;
  /** The right number and two decoys, shuffled: show all three. */
  numbers: number[];
  created_at: string;
  expires_at: string;
}

export interface PushApproverConfig {
  /** https://auth.example.com/t/<tenant> */
  issuer: string;
  signer: PushSigner;
  /** Set after enrolment; keep it with the key. */
  approverId?: string;
  fetch?: typeof fetch;
}

export interface PushApprover {
  readonly approverId: string | undefined;
  /** Enrols this phone for the signed-in user (a sign-in within 5 minutes). Returns recovery codes for a first factor. */
  enrol(accessToken: string, name: string): Promise<{ id: string; recovery_codes?: string[] }>;
  pending(): Promise<PushChallenge[]>;
  approve(challengeId: string, number: number): Promise<"approved" | "denied">;
  /** reported: "that wasn't me", which makes the user's next sign-ins riskier. */
  deny(challengeId: string, reported?: boolean): Promise<"denied">;
}

export class PushError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "PushError";
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

/** A PushSigner over a WebCrypto ECDSA P-256 key pair. */
export function cryptoKeySigner(key: CryptoKeyPair): PushSigner {
  return {
    publicJWK: async () => {
      const { kty, crv, x, y } = await crypto.subtle.exportKey("jwk", key.publicKey);
      return { kty, crv, x, y };
    },
    sign: async (data) => new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, data)),
  };
}

/** A new approver key pair whose private half can sign but can't be exported. */
export function generatePushKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

export function createPushApprover(config: PushApproverConfig): PushApprover {
  const f = config.fetch ?? fetch;
  const base = config.issuer.replace(/\/+$/, "");
  let approverId = config.approverId;

  // The compact JWS every device request carries (ADR-0111).
  async function sign(extra: Record<string, unknown> = {}): Promise<string> {
    if (!approverId) throw new PushError(0, "enrol this device first");
    const input = `${enc({ alg: "ES256", kid: approverId })}.${enc({ aud: `${base}/v1/push`, iat: Math.floor(Date.now() / 1000), jti: jti(), ...extra })}`;
    const sig = await config.signer.sign(new TextEncoder().encode(input));
    if (sig.length !== 64) throw new PushError(0, "the signer must return a 64-byte ES256 signature");
    return `${input}.${b64url(sig)}`;
  }

  async function json<T>(r: Response): Promise<T> {
    if (!r.ok) {
      const p = (await r.json().catch(() => ({}))) as { detail?: string; title?: string };
      throw new PushError(r.status, p.detail || p.title || `push request failed (${r.status})`);
    }
    return (await r.json()) as T;
  }

  async function answer(id: string, body: Record<string, unknown>) {
    const r = await f(`${base}/v1/push/challenges/${encodeURIComponent(id)}`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ answer: await sign({ challenge_id: id, ...body }) }),
    });
    return (await json<{ status: "approved" | "denied" }>(r)).status;
  }

  return {
    get approverId() { return approverId; },
    async enrol(accessToken, name) {
      const r = await f(`${base}/v1/me/push-approvers`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ name, public_key: await config.signer.publicJWK() }),
      });
      const out = await json<{ id: string; recovery_codes?: string[] }>(r);
      approverId = out.id;
      return out;
    },
    async pending() {
      const r = await f(`${base}/v1/push/pending`, { headers: { Authorization: `Push ${await sign()}` } });
      return (await json<{ challenges: PushChallenge[] }>(r)).challenges;
    },
    approve: (id, number) => answer(id, { decision: "approve", number }),
    deny: async (id, reported = false) => (await answer(id, { decision: "deny", number: 0, reported })) as "denied",
  };
}
