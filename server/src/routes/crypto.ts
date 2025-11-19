import express from "express";
import { getServerPublicKey } from "../crypto/kyber";

const router = express.Router();

router.get("/public-key", (_req, res) => {
  const pk = getServerPublicKey();
  const pkBase64 = Buffer.from(pk).toString("base64");
  res.json({ publicKey: pkBase64 });
});

export default router;
