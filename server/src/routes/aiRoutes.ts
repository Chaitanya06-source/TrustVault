import { Router, Response } from 'express';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../middlewares/authMiddleware';
import { AiAdvisoryService } from '../services/aiAdvisoryService';

export const aiRouter = Router();

aiRouter.use(authenticate);

const recommendSchema = z.object({
  documentTitle: z.string().min(1),
  category: z.string().min(1),
  description: z.string().optional(),
  documentId: z.string().uuid().optional()
});

const confirmSchema = z.object({
  documentId: z.string().uuid(),
  advisoryId: z.string().uuid(),
  decision: z.enum(['ACCEPTED', 'REJECTED', 'MODIFIED']),
  confirmedGrants: z.array(
    z.object({
      userId: z.string().uuid(),
      permissionLevel: z.enum(['view', 'edit'])
    })
  )
});

/**
 * POST /api/ai/recommend
 * Generates AI Least-Privilege Access Advisory.
 * Does NOT apply permissions automatically.
 */
aiRouter.post('/recommend', (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = recommendSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Validation failed', details: parsed.error.issues });
      return;
    }

    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const recommendation = AiAdvisoryService.generateRecommendation(
      req.user!,
      parsed.data.documentTitle,
      parsed.data.category,
      parsed.data.description,
      parsed.data.documentId,
      ipAddress,
      userAgent
    );

    res.json({ recommendation });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/ai/confirm
 * Human owner confirms, modifies, or rejects the AI recommendation.
 * Explicitly records the human decision and grants approved permissions into the audit trail.
 */
aiRouter.post('/confirm', (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = confirmSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Validation failed', details: parsed.error.issues });
      return;
    }

    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const result = AiAdvisoryService.confirmDecision(
      req.user!,
      parsed.data.documentId,
      parsed.data.advisoryId,
      parsed.data.decision,
      parsed.data.confirmedGrants,
      ipAddress,
      userAgent
    );

    res.json({
      success: true,
      message: `AI recommendation ${parsed.data.decision.toLowerCase()} and ${result.appliedGrantsCount} permission grant(s) applied.`,
      result
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});
