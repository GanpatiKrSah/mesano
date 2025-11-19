import { MlKem1024 } from "mlkem";

const kem = new MlKem1024();

let serverPublicKey: Uint8Array | null = null;
let serverSecretKey: Uint8Array | null = null;

export async function initKyber(): Promise<void> {
  const [pk, sk] = await kem.generateKeyPair();
  serverPublicKey = pk;
  serverSecretKey = sk;
}

export function getServerPublicKey(): Uint8Array {
  if (!serverPublicKey) throw new Error("Kyber not initialized");
  return serverPublicKey;
}

export async function decapsulate(ciphertext: Uint8Array): Promise<Uint8Array> {
  if (!serverSecretKey) throw new Error("Kyber not initialized");
  return kem.decap(ciphertext, serverSecretKey);
}
