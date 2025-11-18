// scripts/helpers.js

export function fromBase64(b64) {
  return Buffer.from(b64, "base64");
}

export function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

export function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

export function fromHex(hex) {
  return Buffer.from(hex, "hex");
}
