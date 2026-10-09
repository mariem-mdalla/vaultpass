import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma.js";

export async function register(req, res, next) {
  try {
    const { email, authPassword } = req.body;
    if (!email || !authPassword)
      return res.status(400).json({ message: "Email and password required." });

    const exists = await prisma.user.findUnique({ where: { email } });
    if (exists)
      return res.status(409).json({ message: "Account already exists." });

    // bcrypt hash the AUTH password (this is separate from the vault master key)
    const hash = await bcrypt.hash(authPassword, 12);
    const user = await prisma.user.create({
      data: { email, authPasswordHash: hash },
      select: { id: true, email: true, createdAt: true },
    });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.status(201).json({ token, user });
  } catch (err) { next(err); }
}

export async function login(req, res, next) {
  try {
    const { email, authPassword } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });

    // Use constant-time comparison to prevent timing attacks
    const valid = user
      ? await bcrypt.compare(authPassword, user.authPasswordHash)
      : await bcrypt.compare(authPassword, "$2b$12$invalidhashfortimingnoop");

    if (!user || !valid)
      return res.status(401).json({ message: "Invalid credentials." });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (err) { next(err); }
}