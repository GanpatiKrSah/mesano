// src/main.js
import readline from "readline";
import {
  generateKeyPair,
  encapsulate,
  decapsulate,
  encryptMessage,
  decryptMessage,
} from "./algorithms/kyber.js";

// Parse --level argument (defaults to 1024)
const arg = process.argv.find((x) => x.startsWith("--level="));
const level = arg ? parseInt(arg.split("=")[1]) : 1024;

function toHex(buf, limit = 64) {
  if (!buf) return "(undefined)";
  const str = Buffer.from(buf).toString("hex");
  return str.length > limit ? str.slice(0, limit) + "..." : str;
}

async function run() {
  console.log(`\n=== CRYSTALS-KYBER (ML-KEM-${level}) Secure Encryption Demo ===\n`);

  // Input from terminal
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const message = await new Promise((resolve) =>
    rl.question("Enter your message: ", (ans) => resolve(ans))
  );
  rl.close();

  // Generate key pair
  const { publicKey, secretKey } = await generateKeyPair(level);
  console.log("🔑 Generated Kyber key pair:");
  console.log("Public Key:", toHex(publicKey));
  console.log("Secret Key:", toHex(secretKey));

  // Encapsulate (create shared secret)
  const { ciphertext, sharedSecret } = await encapsulate(publicKey, level);
  console.log("\n📦 Encapsulation complete:");
  console.log("Ciphertext:", toHex(ciphertext));
  console.log("Shared Secret (sender):", toHex(sharedSecret, 128));

  // Encrypt message using shared secret
  const { iv, tag, encrypted } = encryptMessage(message, sharedSecret);
  console.log("\n🔒 AES-256-GCM Encryption:");
  console.log("Encrypted Message:", toHex(encrypted, 128));
  console.log("IV:", toHex(iv));
  console.log("Auth Tag:", toHex(tag));

  // Receiver decapsulates ciphertext to recover same shared secret
  const { sharedSecret: recvSecret } = await decapsulate(ciphertext, secretKey, level);
  console.log("\n🔓 Decapsulation complete:");
  console.log("Shared Secret (receiver):", toHex(recvSecret, 128));

  // Decrypt the message
  const decrypted = decryptMessage(encrypted, iv, tag, recvSecret);
  console.log("\n💬 Decrypted Message:", decrypted);

  const match = message === decrypted;
  console.log("\n✅ Match:", match ? "Yes (Perfect!)" : "No (Something’s wrong)");

  console.log("\n--- Summary ---");
  console.log("Algorithm Level: ML-KEM-" + level);
  console.log("Security Strength:", level === 512 ? "≈ AES-128" : level === 768 ? "≈ AES-192" : "≈ AES-256");
  console.log("----------------\n");
}

run().catch((err) => console.error("❌ Error:", err));
