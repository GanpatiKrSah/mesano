// server/src/debug/logTraffic.ts
import { Request, Response, NextFunction } from "express";

export function logTraffic(req: Request, res: Response, next: NextFunction) {
  const start = Date.now();

  // log incoming request
  console.log("=== IN ===");
  console.log(req.method, req.originalUrl);
  console.log("headers:", {
    "content-type": req.headers["content-type"],
    origin: req.headers.origin
  });
  console.log("body:", req.body);

  // hook into res.json to log outgoing response
  const oldJson = res.json.bind(res);
  res.json = (body: any) => {
    const ms = Date.now() - start;
    console.log("=== OUT ===");
    console.log(req.method, req.originalUrl, `(${ms} ms)`);
    console.log("status:", res.statusCode);
    console.log("response body:", body);
    return oldJson(body);
  };

  next();
}
