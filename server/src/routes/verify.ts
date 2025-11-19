import express from "express";
import { pool } from "../config/db";

const router = express.Router();

router.post("/", async (req, res) => {
  const { uid } = req.body as { uid?: string };

  if (!uid || typeof uid !== "string") {
    return res.status(400).json({ ok: false, error: "Invalid uid" });
  }

  try {
    const result = await pool.query(
      "SELECT message_quota FROM users WHERE uid = $1",
      [uid]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ ok: false, error: "User not found" });
    }

    const quota: number = result.rows[0].message_quota;
    if (quota <= 0) {
      return res.status(403).json({ ok: false, error: "No message quota" });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

export default router;
