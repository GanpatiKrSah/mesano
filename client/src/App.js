import React, { useEffect, useState } from "react";

// ---- helpers: hashing and AES-GCM in browser ----

// sha256 of bytes -> hex
async function sha256HexFromBytes(u8) {
  const digest = await window.crypto.subtle.digest("SHA-256", u8);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// sha256 of string -> hex
async function sha256Hex(str) {
  const enc = new TextEncoder();
  const data = enc.encode(str);
  return sha256HexFromBytes(data);
}

// build shared secret = countersign + hash(countersign) + ... up to 32 bytes
async function buildSharedSecret(countersign) {
  const enc = new TextEncoder();

  const csBytes = enc.encode(countersign); // may be shorter than 32
  const csHashHex = await sha256Hex(countersign);
  const csHashBytes = enc.encode(csHashHex); // ASCII hex

  const combined = new Uint8Array(csBytes.length + csHashBytes.length);
  combined.set(csBytes, 0);
  combined.set(csHashBytes, csBytes.length);

  const shared = new Uint8Array(32);
  shared.set(combined.slice(0, 32)); // truncate to 32 bytes

  return shared;
}

async function deriveAesKeyFromCountersign(countersign) {
  const shared = await buildSharedSecret(countersign);
  return window.crypto.subtle.importKey(
    "raw",
    shared,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptAesGcm(plaintext, aesKey) {
  const enc = new TextEncoder();
  const data = enc.encode(plaintext);

  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const cipherBuf = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    data
  );

  const full = new Uint8Array(cipherBuf);
  const authTag = full.slice(full.length - 16);
  const ciphertext = full.slice(0, full.length - 16);

  const toBase64 = bytes =>
    btoa(String.fromCharCode(...bytes));

  return {
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
    authTag: toBase64(authTag)
  };
}

function App() {
  const [serverPublicKey, setServerPublicKey] = useState(null); // Uint8Array
  const [countersign, setCountersign] = useState("");
  const [uid, setUid] = useState("");
  const [aesKey, setAesKey] = useState(null);
  const [verified, setVerified] = useState(false);
  const [message, setMessage] = useState("");
  const [log, setLog] = useState("");

  // load Kyber public key once per session
  useEffect(() => {
    fetch("http://localhost:4000/api/crypto/public-key")
      .then(r => r.json())
      .then(json => {
        const pkBase64 = json.publicKey;
        const bytes = Uint8Array.from(atob(pkBase64), c =>
          c.charCodeAt(0)
        );
        setServerPublicKey(bytes);
      })
      .catch(err => {
        console.error(err);
        setLog("Failed to load server public key");
      });
  }, []);

  async function handleVerify() {
    try {
      setLog("");

      if (!serverPublicKey) {
        setLog("Server public key not loaded yet");
        return;
      }
      if (!countersign) {
        setLog("Enter countersign");
        return;
      }

      // 1) build shared secret bytes
const shared = await buildSharedSecret(countersign);

// 2) uid = sha256(shared secret)
const computedUid = await sha256HexFromBytes(shared);
setUid(computedUid);

// 3) AES key from same shared secret
const key = await window.crypto.subtle.importKey(
  "raw",
  shared,
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"]
);
setAesKey(key);

      // Kyber encapsulation (browser, via esm.sh)
      const { MlKem1024 } = await import("https://esm.sh/mlkem@latest");
      const kem = new MlKem1024();
      const [ciphertext, _shared] = await kem.encap(serverPublicKey);
      // we don't actually need kem ciphertext for verify, but this proves it works
      console.log("Verify Kyber ct len:", ciphertext.length);

      const res = await fetch("http://localhost:4000/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uid: computedUid })
      });

      const json = await res.json();
      if (!res.ok || !json.ok) {
        setVerified(false);
        setLog("Verify failed: " + (json.error || res.status));
        return;
      }

      setVerified(true);
      setLog("Verified. You can send a message.");
    } catch (e) {
      console.error(e);
      setLog("Error during verify");
    }
  }

  async function handleSend() {
    try {
      setLog("");

      if (!verified) {
        setLog("Not verified");
        return;
      }
      if (!aesKey) {
        setLog("AES key missing");
        return;
      }
      if (!message) {
        setLog("Message empty");
        return;
      }

      const { iv, ciphertext, authTag } =
        await encryptAesGcm(message, aesKey);

      const { MlKem1024 } = await import("https://esm.sh/mlkem@latest");
      const kem = new MlKem1024();
      const [kemCt, _shared] = await kem.encap(serverPublicKey);
      const kemCtB64 = btoa(String.fromCharCode(...kemCt));

      const body = {
        uid,
        kemCiphertext: kemCtB64,
        iv,
        authTag,
        ciphertext
      };

      const res = await fetch("http://localhost:4000/api/message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const json = await res.json();
      if (!res.ok || !json.ok) {
        setLog("Send failed: " + (json.error || res.status));
        return;
      }

      setMessage("");
      setLog("Message sent.");
    } catch (e) {
      console.error(e);
      setLog("Error during send");
    }
  }

  return (
    <div style={{ maxWidth: 600, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h2>Mesano secure message (1-side)</h2>

      <div style={{ marginBottom: "1rem" }}>
        <label>
          Countersign:
          <input
            type="password"
            value={countersign}
            onChange={e => setCountersign(e.target.value)}
            style={{ width: "100%", marginTop: "0.25rem" }}
          />
        </label>
        <button onClick={handleVerify} style={{ marginTop: "0.5rem" }}>
          Verify
        </button>
      </div>

      <div>
        <textarea
          placeholder="Write message..."
          value={message}
          onChange={e => setMessage(e.target.value)}
          disabled={!verified}
          rows={6}
          style={{ width: "100%" }}
        />
        <button
          onClick={handleSend}
          disabled={!verified}
          style={{ marginTop: "0.5rem" }}
        >
          Send
        </button>
      </div>

      <div style={{ marginTop: "1rem", color: "darkred" }}>
        {log}
      </div>
    </div>
  );
}

export default App;
