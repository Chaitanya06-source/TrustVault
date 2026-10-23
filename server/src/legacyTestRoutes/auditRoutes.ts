import { Router, Response } from 'express';
import { authenticate, AuthenticatedRequest } from '../legacyTestMiddlewares/authMiddleware';
import { AuditService } from '../services/auditService';
import { getDatabase } from '../db/database';

export const auditRouter = Router();

auditRouter.use(authenticate);

/**
 * GET /api/audit
 * Retrieves audit records. Admin sees system-wide, Owners see activity on their documents.
 */
auditRouter.get('/', (req: AuthenticatedRequest, res: Response) => {
  try {
    const { action, status, documentId, actorId, limit, offset } = req.query;
    const user = req.user!;

    if (user.role === 'viewer') {
      res.status(403).json({ error: 'Access denied: Audit trail is restricted to administrators and document owners' });
      return;
    }

    const filters: any = {
      action: typeof action === 'string' ? action : undefined,
      status: typeof status === 'string' ? status : undefined,
      limit: limit ? parseInt(limit as string, 10) : 50,
      offset: offset ? parseInt(offset as string, 10) : 0
    };

    if (user.role === 'admin') {
      // Admin can inspect all logs
      if (typeof documentId === 'string') filters.documentId = documentId;
      if (typeof actorId === 'string') filters.actorId = actorId;
    } else {
      // Document owner: can only see events related to their documents
      const db = getDatabase();
      const ownedDocs = db
        .prepare('SELECT id FROM documents WHERE owner_id = ?')
        .all(user.id) as Array<{ id: string }>;

      const ownedIds = ownedDocs.map(d => d.id);

      if (typeof documentId === 'string') {
        if (!ownedIds.includes(documentId)) {
          res.status(403).json({ error: 'Forbidden: You do not own this document' });
          return;
        }
        filters.documentId = documentId;
      }
    }

    const result = AuditService.getLogs(filters);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/audit/verify
 * Runs full cryptographic hash chain verification.
 * Confirms whether any row has been altered, deleted, or inserted.
 */
auditRouter.get('/verify', (req: AuthenticatedRequest, res: Response) => {
  try {
    const verification = AuditService.verifyChainIntegrity();
    res.json({ verification });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});
