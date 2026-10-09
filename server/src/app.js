import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";
import vaultRoutes from "./routes/vault.routes.js";
import { errorMiddleware } from "./middleware/error.middleware.js";

dotenv.config();
const app = express();

// helmet adds security headers automatically to every response
// prevents clickjacking, XSS, forces HTTPS etc
app.use(helmet());

// CORS — only allow requests from our React frontend
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));

// Parse JSON bodies — limit 50kb to prevent large payload attacks
app.use(express.json({ limit: "50kb" }));

// Global rate limit — max 100 requests per 15 min per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Stricter rate limit on auth routes — only 10 attempts per 15 min
// Prevents brute force attacks on login
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many attempts. Try again in 15 minutes." },
});

// Mount routes
app.use("/api/auth", authLimiter, authRoutes); // auth limiter only on auth!
app.use("/api/vault", vaultRoutes);

// Error handler — must be last!
app.use(errorMiddleware);

export default app;