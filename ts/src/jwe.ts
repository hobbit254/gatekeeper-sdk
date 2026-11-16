import { compactDecrypt, type KeyLike } from "jose";

/** A decryption key: a WebCrypto CryptoKey (ideally non-extractable) or a jose KeyLike. */
export type DecryptionKey = CryptoKey | KeyLike;

/**
 * innerToken returns the signed JWT inside raw (ADR-0121): raw itself when it is a JWS,
 * else raw decrypted with key (ECDH-ES+A256KW or RSA-OAEP-256, A256GCM).
 */
export async function innerToken(raw: string, key?: DecryptionKey): Promise<string> {
  if (raw.split(".").length !== 5) return raw;
  if (!key) throw new Error("gatekeeper: the token is encrypted and no decryptionKey is configured");
  const { plaintext } = await compactDecrypt(raw, key, {
    keyManagementAlgorithms: ["ECDH-ES+A256KW", "RSA-OAEP-256"], contentEncryptionAlgorithms: ["A256GCM"] });
  return new TextDecoder().decode(plaintext);
}
