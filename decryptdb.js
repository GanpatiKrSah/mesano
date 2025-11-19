// decrypt_prompt.js
import readline from "readline";
import crypto from "crypto";

// sha256(countersign) -> hex
function sha256Hex(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

// shared secret = countersign + sha256(countersign), truncated to 32 bytes
function buildSharedSecret(countersign) {
  const csBytes = Buffer.from(countersign, "utf8");
  const csHashHex = sha256Hex(countersign);
  const csHashBytes = Buffer.from(csHashHex, "utf8");
  const combined = Buffer.concat([csBytes, csHashBytes]);
  return combined.slice(0, 32); // 32 bytes key
}

function decryptAesGcm(countersign, ivHex, cipherHex, authTagHex) {
  const key = buildSharedSecret(countersign);
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const ciphertext = Buffer.from(cipherHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  let dec = decipher.update(ciphertext, undefined, "utf8");
  dec += decipher.final("utf8");
  return dec;
}

// ---------- CLI prompt ----------

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question("Countersign: ", countersign => {
  rl.question("IV (hex): ", ivHex => {
    rl.question("Cipher (hex): ", cipherHex => {
      rl.question("Auth tag (hex): ", authTagHex => {
        try {
          const plaintext = decryptAesGcm(
            countersign.trim(),
            ivHex.trim(),
            cipherHex.trim(),
            authTagHex.trim()
          );
          console.log("Decrypted message:", plaintext);
        } catch (e) {
          console.error("Decrypt error:", e.message);
        } finally {
          rl.close();
        }
      });
    });
  });
});
