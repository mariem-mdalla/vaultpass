import jwt from "jsonwebtoken";

export function protect(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer "))
    return res.status(401).json({ message: "No token provided." });

  try {
    req.user = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Token invalid or expired." });
  }
}

export function errorMiddleware(err, req, res, next) {
  console.error(err.stack);
  const status = err.status || 500;
  res.status(status).json({
    message: process.env.NODE_ENV === "production"
      ? "Something went wrong."   // never leak stack traces in prod
      : err.message,
  });
}