import { Router } from "express";
import { createVault, getVaults, updateVault, deleteVault } from "../controllers/vault.controller.js";
import {protect} from "../middleware/auth.middleware.js";

const router = Router();

router.get("/",protect, getVaults);
router.post("/", protect, createVault);
router.put("/:id", protect, updateVault);
router.delete("/:id", protect, deleteVault);

export default router;