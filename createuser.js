const crypto = require("crypto");

function buildShared(countersign) {
  const csBytes = Buffer.from(countersign, "utf8");
  const hashHex = crypto
    .createHash("sha256")
    .update(countersign, "utf8")
    .digest("hex");
  const hashBytes = Buffer.from(hashHex, "utf8");
  const combined = Buffer.concat([csBytes, hashBytes]);
  return combined.slice(0, 32);
}

const cs = "HelloWorld1234$#";
const shared = buildShared(cs);
const uid = crypto.createHash("sha256").update(shared).digest("hex");
console.log("uid =", uid);