import { Router, Response } from "express";
import {
  authenticateRequest,
  requireUser,
  AuthenticatedRequest,
} from "../middleware/rbac";
import { getAccountByQuipayId } from "../db/queries";

export const accountsRouter = Router();

accountsRouter.use(authenticateRequest, requireUser);

/**
 * GET /api/accounts/me
 * Returns the caller's Quipay ID and basic account info, resolved from the
 * verified Privy identity by authenticateRequest.
 */
accountsRouter.get("/me", (req: AuthenticatedRequest, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({
    quipayId: req.user.quipayId,
    email: req.user.email ?? null,
  });
});

const QUIPAY_ID_RE = /^QP\d+$/i;

/**
 * GET /api/accounts/lookup/:quipayId
 * Resolves another account by its QP ID — used before adding someone to a
 * roster/stream, so the caller only ever needs their QP ID, never a raw
 * wallet address. Returns 404 rather than leaking whether the account exists
 * beyond that.
 */
accountsRouter.get(
  "/lookup/:quipayId",
  async (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const quipayId = req.params.quipayId?.trim().toUpperCase() ?? "";
    if (!QUIPAY_ID_RE.test(quipayId)) {
      return res.status(400).json({ error: "Invalid QP ID" });
    }

    const account = await getAccountByQuipayId(quipayId);
    if (!account) {
      return res.status(404).json({ error: "No account found with that QP ID" });
    }

    res.json({
      quipayId: account.quipayId,
      email: account.email,
      walletStellar: account.walletStellar,
      walletBase: account.walletBase,
    });
  },
);
