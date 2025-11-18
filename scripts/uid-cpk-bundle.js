// scripts/uid-cpk-bundle.js

import { toBase64, fromBase64 } from "./helpers.js";

/**
 * Placeholder encryption: serializes to JSON + base64
 */
export function encryptUidAndCpkWithServerKey(uidBytes, clientPublicKeyBytes) {
  const bundleJson = {
    uid: toBase64(uidBytes),
    cpk: toBase64(clientPublicKeyBytes),
    note: "placeholder encryption"
  };

  const jsonString = JSON.stringify(bundleJson);
  const encryptedBundleBase64 = toBase64(Buffer.from(jsonString, "utf8"));

  return { bundleJson, encryptedBundleBase64 };
}

/**
 * Reverse of above
 */
export function decryptUidAndCpkWithServerKey(encB64) {
  const buf = fromBase64(encB64);
  const json = JSON.parse(buf.toString("utf8"));

  return {
    uidBytes: fromBase64(json.uid),
    clientPublicKeyBytes: fromBase64(json.cpk),
    debug: json
  };
}
