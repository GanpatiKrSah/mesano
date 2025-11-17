// src/run.js

import readline from "readline";
import {
  buildClientWorkflow,
  decryptMessageFromCiphertext,
  decryptUidAndCpkWithServerKey,
  SERVER_PUBLIC_KEY_BASE64,
} from "./payload.js";

function ask(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

// Mock backend user check – always true
async function mockCheckUserExists(uidHex) {
  // Would lookup uid in database; here: pretend it exists.
  return true;
}

async function sendingFlow() {
  console.log("=== SENDING FLOW (Client side workflow - sending message) ===\n");

  // 1) Get countersign from user
  const countersign = await ask("Enter countersign (20–32 characters): ");

  console.log("\n[Step 1] Building initial workflow (derive hash, ss, uid, keys)…");

  // Build with empty message just to get uid
  let tempWorkflow;
  try {
    tempWorkflow = await buildClientWorkflow(countersign, "");
  } catch (err) {
    console.error("Error deriving client values:", err.message);
    return;
  }

  console.log("countersign:            ", tempWorkflow.countersign);
  console.log("hash (SHA-256):         ", tempWorkflow.hashHex);
  console.log("sharedsecret (ss):      ", tempWorkflow.sharedSecretHex);
  console.log("uid (sha256(ss)):       ", tempWorkflow.uidHex);
  console.log("Initial Vector (ivrandom):", tempWorkflow.ivRandomHex);

  console.log("\n[Step 2] Checking user details in backend (mock using uid)...");
  const exists = await mockCheckUserExists(tempWorkflow.uidHex);
  if (!exists) {
    console.log("Receiver does NOT exist (mock).");
    return;
  }
  console.log("Receiver exists (mock).\n");

  // 2) Ask message
  const message = await ask("Enter message to send: ");

  console.log("\n[Step 3] Building full payload with message…");
  let workflow;
  try {
    workflow = await buildClientWorkflow(countersign, message);
  } catch (err) {
    console.error("Error building full workflow:", err.message);
    return;
  }

  console.log("\n=== OUTPUT (diagram order) ===");

  console.log("\n[Client] Input");
  console.log("countersign:            ", workflow.countersign);

  console.log("\n[Client] Derived hashes & secrets");
  console.log("hash (hased(sha256)):   ", workflow.hashHex);
  console.log("sharedsecret (ss):      ", workflow.sharedSecretHex);
  console.log("uid = secretkey.sha256: ", workflow.uidHex);
  console.log("UID (SHA-512(sharedKey)) [extra]:", workflow.internalUIDHex);
  console.log("Initial Vector (ivrand):", workflow.ivRandomHex);

  console.log("\n[Client] ML-KEM keys");
  console.log("client public key (b64):", workflow.clientPublicKeyBase64);
  console.log("client public key (hex):", workflow.clientPublicKeyHex);
  console.log("client private key (b64):", workflow.clientSecretKeyBase64);

  console.log("\n[Client] Server key");
  console.log("server public key (b64):", workflow.serverPublicKeyBase64);

  console.log("\n[Client] (uid + cpk).encrypt(spk)  (placeholder)");
  console.log("bundle JSON (uid+cpk):  ", workflow.uidCpkBundleJson);
  console.log("encrypted bundle (b64): ", workflow.uidCpkEncryptedBase64);

  console.log("\n[Client] Message -> CipherMessage -> encrypted ciphermessage");
  console.log("Message (plaintext):    ", workflow.cipherMessage.message);
  console.log("CipherMessage.iv (hex): ", workflow.cipherMessage.ivHex);
  console.log("CipherMessage.ss (hex): ", workflow.cipherMessage.ssHex);
  console.log("AES IV (hex):           ", workflow.aesIvHex);
  console.log("encrypted ciphermessage:", workflow.encryptedCipherMessageHex);

  console.log("\n=== SENDING FLOW COMPLETE ===");
  console.log("\nCopy the following values for the decryption test:");
  console.log("  encrypted ciphermessage (hex):", workflow.encryptedCipherMessageHex);
  console.log("  AES IV (hex):                 ", workflow.aesIvHex);
  console.log("  countersign:                  ", workflow.countersign);
  console.log("  encrypted bundle (uid+cpk, b64):", workflow.uidCpkEncryptedBase64);
  console.log();
}

async function decryptionFlow() {
  console.log("=== DECRYPTION FLOW ===\n");

  // 1) Ask for encrypted bundle (uid+cpk) and show that we can parse it "server-side"
  const encryptedBundleBase64 = await ask("Paste encrypted bundle (uid+cpk, base64) [or ENTER to skip]: ");

  if (encryptedBundleBase64 && encryptedBundleBase64.trim() !== "") {
    const trimmed = encryptedBundleBase64.trim();
    const { uidBytes, clientPublicKeyBytes, debug } =
      decryptUidAndCpkWithServerKey(trimmed);

    console.log("\n[Server] Parsed (uid+cpk) bundle:");
    console.log("uid (hex):              ", uidBytes.toString("hex"));
    console.log("client public key (hex):", clientPublicKeyBytes.toString("hex"));
    console.log("debug info:             ", debug);
  } else {
    console.log("[Server] Skipping (uid+cpk) bundle parsing.");
  }

  // 2) Ask for encrypted ciphermessage + AES IV + countersign
  const encryptedCipherHex = await ask("\nEnter encrypted ciphermessage (hex): ");
  const ivHex = await ask("Enter AES IV (hex): ");
  const countersign = await ask("Enter countersign (same used for encryption): ");

  try {
    const plaintext = decryptMessageFromCiphertext(countersign, encryptedCipherHex.trim(), ivHex.trim());
    console.log("\n[Client] Decrypted message:", plaintext);
  } catch (err) {
    console.error("\n[Client] Decryption failed:", err.message);
  }

  console.log("\n=== DECRYPTION FLOW COMPLETE ===");
}

async function main() {
  console.log("Server public key currently configured (base64):");
  console.log(SERVER_PUBLIC_KEY_BASE64, "\n");

  const mode = await ask("Choose mode: [1] Send (encrypt)  [2] Decrypt: ");
  if (mode.trim() === "1") {
    await sendingFlow();
  } else if (mode.trim() === "2") {
    await decryptionFlow();
  } else {
    console.log("Unknown mode. Exiting.");
  }
}

main().catch(err => {
  console.error("Fatal error in run.js:", err);
});
