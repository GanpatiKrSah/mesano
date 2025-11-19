import express from "express";
import { pool } from "../config/db";
import { decapsulate } from "../crypto/kyber";

const router = express.Router();

router.post("/", async (req, res) => {
  const { uid, kemCiphertext, iv, authTag, ciphertext } = req.body as {
    uid?: string;
    kemCiphertext?: string;
    iv?: string;
    authTag?: string;
    ciphertext?: string;
  };

  if (!uid || !kemCiphertext || !iv || !authTag || !ciphertext) {
    return res.status(400).json({ ok: false, error: "Missing fields" });
  }

  try {
    const kemCtBytes = Buffer.from(kemCiphertext, "base64");
    await decapsulate(kemCtBytes); // just validates

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const userRes = await client.query(
        "SELECT message_quota FROM users WHERE uid = $1 FOR UPDATE",
        [uid]
      );

      if (userRes.rowCount === 0) {
        await client.query("ROLLBACK");
        client.release();
        return res.status(404).json({ ok: false, error: "User not found" });
      }

      const quota: number = userRes.rows[0].message_quota;
      if (quota <= 0) {
        await client.query("ROLLBACK");
        client.release();
        return res.status(403).json({ ok: false, error: "No message quota" });
      }

      const ivHex = Buffer.from(iv, "base64").toString("hex");
      const cipherHex = Buffer.from(ciphertext, "base64").toString("hex");
      const authTagHex = Buffer.from(authTag, "base64").toString("hex");

      await client.query(
        "INSERT INTO messages (user_id, iv_hex, cipher_hex, auth_tag_hex) VALUES ($1, $2, $3, $4)",
        [uid, ivHex, cipherHex, authTagHex]
      );

      await client.query(
        "UPDATE users SET message_quota = message_quota - 1 WHERE uid = $1",
        [uid]
      );

      await client.query("COMMIT");
      client.release();

      return res.json({ ok: true });
    } catch (e) {
      await client.query("ROLLBACK");
      client.release();
      console.error(e);
      return res.status(500).json({ ok: false, error: "Server error" });
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

export default router;
