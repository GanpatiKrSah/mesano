import { Pool } from "pg";

export const pool = new Pool({
  user: "postgres",
  host: "localhost",   // use the same host as pgAdmin, not "localhost" if it's different
  database: "postgres",       // or "postgres" if that's the DB you are querying
  password: "NewStrongPassword123",
  port: 5432
});
