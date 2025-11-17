// src/payload.js

import crypto from "crypto";
import { generateKeyPair } from "../algorithms/kyber.js";
import { encryptAES256, decryptAES256 } from "../algorithms/aes-encryption.js";
import { generateSharedKey } from "../scripts/shared-key-generator.js";

// === CONFIG ===

// ML-KEM levelgit branch
const KYBER_LEVEL = 768;

// Server public key will be provided as BASE64 string.
// Replace the placeholder value below with your real base64 key.
export const SERVER_PUBLIC_KEY_BASE64 =
  "REPLACE_WITH_SERVER_PUBLIC_KEY_BASE64";

// === HELPERS ===

function fromBase64(b64) {
  return Buffer.from(b64, "base64");
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function fromHex(hex) {
  return Buffer.from(hex, "hex");
}

/**
 * Derive all client-side secrets from countersign:
 *  - hash = SHA-256(countersign)
 *  - sharedSecret (ss) = generateSharedKey(countersign).sharedKey
 *  - uid = SHA-256(sharedSecret)
 *  - ivRandom = random 16 bytes (used only for showing in flow; AES uses its own ivHex)
 */
export function deriveClientSecrets(countersign) {
  // 1) Hash of countersign
  const hash = crypto.createHash("sha256").update(countersign, "utf8").digest();

  // 2) Shared key / secret from countersign
  const { sharedKey, UID } = generateSharedKey(countersign);

  if (sharedKey === -1) {
    throw new Error("Countersign too short (< 20 bytes). Please enter 20–32 characters.");
  }
  if (sharedKey === 2) {
    throw new Error("Countersign too long (> 32 bytes). Please enter 20–32 characters.");
  }

  const sharedSecret = Buffer.from(sharedKey); // 32 bytes

  // 3) uid = sha256(sharedSecret)
  const uid = crypto.createHash("sha256").update(sharedSecret).digest();

  // 4) IV for diagram (separate from AES IV)
  const ivRandom = crypto.randomBytes(16);

  return {
    hash,
    sharedSecret,
    uid,
    ivRandom,
    internalUID: UID, // SHA-512(sharedKey), for reference
  };
}

/**
 * Simulated "(uid + cpk).encrypt(spk)" using server public key.
 *
 * Real implementation: KEM+AEAD with SERVER_PUBLIC_KEY.
 * Here: { uid: base64(uid), cpk: base64(cpk) } -> JSON -> base64.
 */
export function encryptUidAndCpkWithServerKey(uid, clientPublicKeyBytes) {
  const serverPubKeyBytes = fromBase64(SERVER_PUBLIC_KEY_BASE64);
  const bundle = {
    uid: toBase64(uid),
    cpk: toBase64(clientPublicKeyBytes),
    // we include server key hash for debug to show it's used
    spkSha256: crypto.createHash("sha256").update(serverPubKeyBytes).digest("hex"),
  };
  const json = JSON.stringify(bundle);
  const encryptedBundleBase64 = toBase64(Buffer.from(json, "utf8"));
  return { bundleJson: json, encryptedBundleBase64 };
}

/**
 * Reverse of encryptUidAndCpkWithServerKey (placeholder).
 * Takes the base64 "encrypted" bundle and returns { uidBytes, clientPublicKeyBytes }.
 */
export function decryptUidAndCpkWithServerKey(encryptedBundleBase64) {
  const buf = fromBase64(encryptedBundleBase64);
  const json = buf.toString("utf8");
  const obj = JSON.parse(json);
  const uidBytes = fromBase64(obj.uid);
  const clientPublicKeyBytes = fromBase64(obj.cpk);
  return { uidBytes, clientPublicKeyBytes, debug: obj };
}

/**
 * Build full client-side workflow for sending a message.
 *
 * Returns everything needed for display and later decryption:
 *  - countersign, hash, sharedSecret, uid, ivRandom
 *  - client ML-KEM keys
 *  - server public key base64
 *  - (uid+cpk).encrypt(spk) placeholder
 *  - AES-256-CBC encrypted ciphermessage (with ivHex)
 */
export async function buildClientWorkflow(countersign, message) {
  // Derive secrets
  const { hash, sharedSecret, uid, ivRandom, internalUID } =
    deriveClientSecrets(countersign);

  // Generate client ML-KEM key pair
  const { publicKey: clientPublicKey, secretKey: clientSecretKey } =
    await generateKeyPair(KYBER_LEVEL);

  const clientPublicKeyBytes = Buffer.from(clientPublicKey);
  const clientSecretKeyBytes = Buffer.from(clientSecretKey);

  // Simulate (uid + cpk).encrypt(spk)
  const { bundleJson, encryptedBundleBase64 } =
    encryptUidAndCpkWithServerKey(uid, clientPublicKeyBytes);

  // Encrypt message with AES-256-CBC using sharedSecret as key
  const { iv: aesIvHex, encryptedData: encryptedCipherMessageHex } =
    encryptAES256(message, sharedSecret);

  // CipherMessage structure (conceptual)
  const cipherMessage = {
    message,
    ivHex: aesIvHex,
    ssHex: toHex(sharedSecret),
  };

  return {
    // Input
    countersign,

    // Derived values
    hashHex: toHex(hash),
    sharedSecretHex: toHex(sharedSecret),
    uidHex: toHex(uid),
    internalUIDHex: toHex(internalUID),
    ivRandomHex: toHex(ivRandom),

    // Keys
    clientPublicKeyBase64: toBase64(clientPublicKeyBytes),
    clientPublicKeyHex: toHex(clientPublicKeyBytes),
    clientSecretKeyBase64: toBase64(clientSecretKeyBytes),

    serverPublicKeyBase64: SERVER_PUBLIC_KEY_BASE64,

    // (uid+cpk).encrypt(spk)
    uidCpkBundleJson: bundleJson,
    uidCpkEncryptedBase64: encryptedBundleBase64,

    // CipherMessage + encrypted ciphermessage
    cipherMessage,
    aesIvHex,
    encryptedCipherMessageHex,
  };
}

/**
 * Decrypt AES-256-CBC encrypted ciphermessage using countersign + ivHex.
 * This is the "client" decryption step:
 *  - Recompute sharedSecret from countersign (same as in deriveClientSecrets)
 *  - Use decryptAES256(encryptedCipherMessageHex, sharedSecret, ivHex)
 */
export function decryptMessageFromCiphertext(countersign, encryptedCipherMessageHex, ivHex) {
  const { sharedSecret } = deriveClientSecrets(countersign);
  const plaintext = decryptAES256(encryptedCipherMessageHex, sharedSecret, ivHex);
  return plaintext;
}
