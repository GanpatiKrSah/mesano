import express from "express";
import cors from "cors";
import cryptoRoutes from "./routes/crypto";
import verifyRoutes from "./routes/verify";
import messageRoutes from "./routes/message";
import { logTraffic } from "./debug/logTraffic";

const app = express();

app.use(cors());
app.use(express.json());

// add this line:
app.use(logTraffic);

app.use("/api/crypto", cryptoRoutes);
app.use("/api/verify", verifyRoutes);
app.use("/api/message", messageRoutes);

export default app;
