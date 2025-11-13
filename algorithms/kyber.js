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
