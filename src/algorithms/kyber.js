// src/algorithms/kyber.js
import { MlKem512, MlKem768, MlKem1024 } from "mlkem";
import crypto from "crypto";

// --- Select correct Kyber variant ---
function getKem(level) {
  switch (level) {
    case 512:
      return new MlKem512();
    case 768:
      return new MlKem768();
    case 1024:
    default:
      return new MlKem1024();
  }
}

// === KYBER KEM FUNCTIONS ===
export async function generateKeyPair(level = 768) {
  const kem = getKem(level);
  const [publicKey, secretKey] = await kem.generateKeyPair();
  return { publicKey, secretKey };
}

export async function encapsulate(publicKey, level = 768) {
  const kem = getKem(level);
  const [ciphertext, sharedSecret] = await kem.encap(publicKey);
  return { ciphertext, sharedSecret };
}

export async function decapsulate(ciphertext, secretKey, level = 768) {
  const kem = getKem(level);
  const sharedSecret = await kem.decap(ciphertext, secretKey);
  return { sharedSecret };
}

// === AES-256-GCM encryption using the shared secret ===
export function encryptMessage(message, sharedSecret) {
  const key = sharedSecret.slice(0, 32); // 256-bit AES key
  const iv = crypto.randomBytes(12);     // Random 96-bit IV
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(message, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return { iv, tag, encrypted };
}

export function decryptMessage(encrypted, iv, tag, sharedSecret) {
  const key = sharedSecret.slice(0, 32);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
