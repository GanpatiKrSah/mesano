// scripts/decryption-flow.js

import { deriveClientSecrets } from "./key-derivation.js";
import { decryptAES256 } from "../algorithms/aes-encryption.js";

/**
 * Decrypts AES-256-GCM encrypted data produced by buildClientWorkflow.
 * decryptAES256(encryptedHex, keyBuffer, ivHex, authTagHex)
 */
export function decryptMessageFromCiphertext(countersign, encryptedHex, ivHex, authTagHex) {
  const { sharedSecret } = deriveClientSecrets(countersign);

  // decryptAES256 now expects authTagHex as fourth parameter
  const plaintext = decryptAES256(encryptedHex, sharedSecret, ivHex, authTagHex);
  return plaintext;
}
