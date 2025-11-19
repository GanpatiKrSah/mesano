import app from "./app";
import { initKyber } from "./crypto/kyber";

const PORT = 4000;

async function main() {
  await initKyber();
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

main().catch(err => {
  console.error("Fatal:", err);
  process.exit(1);
});
