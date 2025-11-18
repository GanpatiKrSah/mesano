// scripts/key-derivation.js

import crypto from "crypto";
import { generateSharedKey } from "./shared-key-generator.js";

export const SERVER_PUBLIC_KEY_BASE64 = "REPLACE_WITH_SERVER_PUBLIC_KEY_BASE64";

/**
 * Derive client secrets from countersign
 */
export function deriveClientSecrets(countersign) {
  // SHA-256(countersign)
  const hash = crypto.createHash("sha256").update(countersign, "utf8").digest();

  // Shared key (32 bytes)
  const { sharedKey, UID } = generateSharedKey(countersign);

  if (sharedKey === -1) throw new Error("Countersign too short (<20 chars)");
  if (sharedKey === 2) throw new Error("Countersign too long (>32 chars)");

  const sharedSecret = Buffer.from(sharedKey);

  // uid = SHA-256(sharedSecret)
  const uid = crypto.createHash("sha256").update(sharedSecret).digest();

  const ivRandom = crypto.randomBytes(16);

  return {
    hash,
    sharedSecret,
    uid,
    ivRandom,
    internalUID: UID,
  };
}
