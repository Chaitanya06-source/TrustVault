import { Router, Response } from 'express';
import {
  authenticate,
  AuthenticatedRequest,
} from '../middlewares/authMiddleware';
import { PgAuditService } from '../services/auditService.pg';
import { postgresQuery } from '../db/postgres';

export const auditRouter = Router();

auditRouter.use(authenticate);

auditRouter.get(
  '/',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { action, status, documentId, actorId, limit, offset } = req.query;
      const user = req.user!;

      if (user.role === 'viewer') {
        res.status(403).json({
          error: 'Access denied: Audit trail is restricted to administrators and document owners',
        });
        return;
      }

      const filters: {
        action?: string;
        status?: string;
        documentId?: string;
        actorId?: string;
        limit?: number;
        offset?: number;
      } = {
        action: typeof action === 'string' ? action : undefined,
        status: typeof status === 'string' ? status : undefined,
        limit: limit ? Number.parseInt(limit as string, 10) : 50,
        offset: offset ? Number.parseInt(offset as string, 10) : 0,
      };

      if (user.role === 'admin') {
        if (typeof documentId === 'string') {
          filters.documentId = documentId;
        }
        if (typeof actorId === 'string') {
          filters.actorId = actorId;
        }
      } else {
        const ownedDocs = await postgresQuery<{ id: string }>(
          'SELECT id FROM documents WHERE owner_id = $1',
          [user.id],
        );

        const ownedIds = ownedDocs.rows.map((doc) => doc.id);

        if (typeof documentId === 'string') {
          if (!ownedIds.includes(documentId)) {
            res.status(403).json({
              error: 'Forbidden: You do not own this document',
            });
            return;
          }
          filters.documentId = documentId;
        } else {
          // Restrict document-owner audit results to their own documents.
          // The service currently filters only one document ID, so require
          // a specific document for this role.
          res.status(400).json({
            error: 'Document owners must specify a documentId',
          });
          return;
        }
      }

      const result = await PgAuditService.getLogs(filters);
      res.json(result);
    } catch (err: unknown) {
      console.error('[Audit] Could not retrieve logs:', err);
      res.status(500).json({ error: 'Unable to retrieve audit logs' });
    }
  },
);

auditRouter.get(
  '/verify',
  async (_req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const verification = await PgAuditService.verifyChainIntegrity();

      // Preserve the nested response while also supporting clients expecting top-level fields.
      // The cryptographic verification logic remains unchanged.
      res.json({ ...verification, verification });
    } catch (err: unknown) {
      console.error('[Audit] Chain verification failed:', err);
      res.status(500).json({ error: 'Unable to verify audit chain' });
    }
  },
);
