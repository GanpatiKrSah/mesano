// src/main.js

import readline from "readline";
import {
  buildClientWorkflow
} from "../scripts/encryption-flow.js";

import {
  decryptMessageFromCiphertext
} from "../scripts/decryption-flow.js";

import {
  decryptUidAndCpkWithServerKey
} from "../scripts/uid-cpk-bundle.js";

import {
  SERVER_PUBLIC_KEY_BASE64
} from "../scripts/key-derivation.js";

function ask(question) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise(resolve => rl.question(question, ans => {
    rl.close();
    resolve(ans);
  }));
}

// mock backend
async function mockCheckUserExists() { return true; }

async function sendingFlow() {
  console.log("=== SENDING FLOW ===\n");

  const countersign = await ask("Enter countersign (20–32 chars): ");

  // Build temp to compute uid and validate countersign
  let temp;
  try {
    temp = await buildClientWorkflow(countersign, "");
  } catch (e) {
    console.error("Error:", e.message);
    return;
  }

  console.log("uid:", temp.uidHex);
  console.log("Checking mock backend...");
  await mockCheckUserExists(temp.uidHex);

  const message = await ask("Enter message to send: ");

  const workflow = await buildClientWorkflow(countersign, message);

  console.log("\n=== OUTPUT ===");
  console.log("Encrypted (hex):", workflow.encryptedCipherMessageHex);
  console.log("AES IV (hex):    ", workflow.aesIvHex);
  console.log("Auth Tag (hex):  ", workflow.authTagHex); // NEW: show auth tag
  console.log("Countersign:     ", workflow.countersign);
  console.log("Encrypted bundle (uid+cpk, base64):", workflow.uidCpkEncryptedBase64);
  console.log();
}

async function decryptionFlow() {
  console.log("=== DECRYPT ===");

  const encBundle = await ask("Paste encrypted bundle (base64) [or ENTER to skip]: ");

  if (encBundle.trim() !== "") {
    const parsed = decryptUidAndCpkWithServerKey(encBundle.trim());
    console.log("Parsed uid (hex):", parsed.uidBytes.toString("hex"));
    console.log("Parsed cpk (hex):", parsed.clientPublicKeyBytes.toString("hex"));
    console.log("debug info:", parsed.debug);
  }

  const encHex = await ask("Encrypted message (hex): ");
  const ivHex = await ask("AES IV (hex): ");
  const authTagHex = await ask("Auth Tag (hex): "); // NEW: prompt for auth tag
  const countersign = await ask("Countersign: ");

  try {
    const plaintext = decryptMessageFromCiphertext(
      countersign,
      encHex.trim(),
      ivHex.trim(),
      authTagHex.trim()
    );
    console.log("\n[Client] Decrypted message:", plaintext);
  } catch (e) {
    console.error("\n[Client] Decryption failed:", e.message);
  }
}

async function main() {
  console.log("Server public key:", SERVER_PUBLIC_KEY_BASE64 || "(not configured)\n");

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
  console.error("Fatal error in main.js:", err);
});
