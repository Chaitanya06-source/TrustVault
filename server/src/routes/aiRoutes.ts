import { Router, Response } from 'express';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../middlewares/authMiddleware';
import { AiAdvisoryService } from '../services/aiAdvisoryService.pg';

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

aiRouter.post('/recommend', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = recommendSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation failed',
        details: parsed.error.issues
      });
      return;
    }

    const ipAddress =
      (req.headers['x-forwarded-for'] as string) ||
      req.socket.remoteAddress ||
      '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const recommendation = await AiAdvisoryService.generateRecommendation(
      req.user!,
      parsed.data.documentTitle,
      parsed.data.category,
      parsed.data.description,
      parsed.data.documentId,
      ipAddress,
      userAgent
    );

    res.json({ recommendation });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Internal server error';
    res.status(500).json({ error: message });
  }
});

aiRouter.post('/confirm', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = confirmSchema.safeParse(req.body);

    if (!parsed.success) {
      res.status(400).json({
        error: 'Validation failed',
        details: parsed.error.issues
      });
      return;
    }

    const ipAddress =
      (req.headers['x-forwarded-for'] as string) ||
      req.socket.remoteAddress ||
      '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const result = await AiAdvisoryService.confirmDecision(
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
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Request failed';
    res.status(400).json({ error: message });
  }
});
