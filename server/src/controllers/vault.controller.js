import { prisma } from "../lib/prisma.js";

// GET all entries for logged in user
export async function getVaults(req, res, next) {
  try {
    // req.user.id comes from the protect middleware (JWT token)
    const entries = await prisma.entry.findMany({
      where: { userId: req.user.id } // only get THIS user's entries
    });
    res.json(entries);
  } catch (err) { next(err); }
}

// CREATE a new encrypted entry
export async function createVault(req, res, next) {
  try {
    const { encrypted, iv } = req.body;
    // encrypted = AES-GCM ciphertext (encrypted in browser)
    // iv = initialization vector used during encryption
    // server never sees the plaintext!
    const entry = await prisma.entry.create({
      data: {
        userId: req.user.id,
        encrypted, // just storing the gibberish blob
        iv         // needed to decrypt later
      }
    });
    res.status(201).json(entry);
  } catch (err) { next(err); }
}

// UPDATE an existing entry
export async function updateVault(req, res, next) {
  try {
    // First check the entry exists AND belongs to this user
    const entry = await prisma.entry.findUnique({
      where: { id: req.params.id }
    });

    if (!entry || entry.userId !== req.user.id)
      return res.status(404).json({ message: "Entry not found." });

    const { encrypted, iv } = req.body;
    const updated = await prisma.entry.update({
      where: { id: req.params.id },
      data: { encrypted, iv }
    });
    res.json(updated);
  } catch (err) { next(err); }
}

// DELETE an entry
export async function deleteVault(req, res, next) {
  try {
    // Check ownership before deleting!
    const entry = await prisma.entry.findUnique({
      where: { id: req.params.id }
    });

    if (!entry || entry.userId !== req.user.id)
      return res.status(404).json({ message: "Entry not found." });

    await prisma.entry.delete({
      where: { id: req.params.id }
    });
    res.status(204).end(); // 204 = success, no content to return
  } catch (err) { next(err); }
}