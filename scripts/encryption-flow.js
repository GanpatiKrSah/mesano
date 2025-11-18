// scripts/encryption-flow.js

import { deriveClientSecrets } from "./key-derivation.js";
import { encryptAES256 } from "../algorithms/aes-encryption.js";
import { generateKeyPair } from "../algorithms/kyber.js";
import { encryptUidAndCpkWithServerKey } from "./uid-cpk-bundle.js";
import { toHex, toBase64 } from "./helpers.js";

const KYBER_LEVEL = 768;

export async function buildClientWorkflow(countersign, message) {
  const { hash, sharedSecret, uid, ivRandom, internalUID } =
    deriveClientSecrets(countersign);

  // Generate ML-KEM keypair (client)
  const { publicKey, secretKey } = await generateKeyPair(KYBER_LEVEL);
  const cpkBytes = Buffer.from(publicKey);
  const cskBytes = Buffer.from(secretKey);

  // (uid + cpk).encrypt(spk) — placeholder serializer
  const { bundleJson, encryptedBundleBase64 } =
    encryptUidAndCpkWithServerKey(uid, cpkBytes);

  // AES-256-GCM encryption (note: encryptAES256 now returns { iv, encryptedData, authTag })
  const {
    iv: aesIvHex,
    encryptedData: encryptedCipherMessageHex,
    authTag: authTagHex
  } = encryptAES256(message, sharedSecret);

  return {
    // Input
    countersign,

    // Derived values (hex)
    hashHex: toHex(hash),
    sharedSecretHex: toHex(sharedSecret),
    uidHex: toHex(uid),
    internalUIDHex: toHex(internalUID),
    ivRandomHex: toHex(ivRandom),

    // Keys
    clientPublicKeyBase64: toBase64(cpkBytes),
    clientPublicKeyHex: toHex(cpkBytes),
    clientSecretKeyBase64: toBase64(cskBytes),

    serverPublicKeyBase64: process.env.SERVER_PUBLIC_KEY_BASE64 || "",

    // (uid+cpk).encrypt(spk)
    uidCpkBundleJson: bundleJson,
    uidCpkEncryptedBase64: encryptedBundleBase64,

    // CipherMessage + encrypted ciphermessage (GCM includes authTag)
    cipherMessage: {
      message,
      ivHex: aesIvHex,
      ssHex: toHex(sharedSecret),
      authTagHex, // NEW: store auth tag with cipherMessage
    },

    // Raw outputs
    aesIvHex,
    encryptedCipherMessageHex,
    authTagHex,
  };
}
