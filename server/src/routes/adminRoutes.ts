import { Router, Response } from 'express';
import {
  authenticate,
  requireRole,
  AuthenticatedRequest,
} from '../middlewares/authMiddleware';
import { PgAuditService } from '../services/auditService.pg';
import { postgresQuery } from '../db/postgres';

export const adminRouter = Router();

adminRouter.use(authenticate);
adminRouter.use(requireRole('admin'));

adminRouter.get(
  '/alerts',
  async (_req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const alerts = await PgAuditService.getSecurityAlerts();
      res.json({ alerts });
    } catch (err: unknown) {
      console.error('[Admin] Could not retrieve alerts:', err);
      res.status(500).json({ error: 'Unable to retrieve security alerts' });
    }
  },
);

adminRouter.get(
  '/metrics',
  async (_req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const [docResult, auditResult, userResult] = await Promise.all([
        postgresQuery<{
          total_documents: string;
          total_storage_bytes: string;
        }>(`
          SELECT COUNT(*) AS total_documents,
                 COALESCE(SUM(file_size_bytes), 0) AS total_storage_bytes
          FROM documents
        `),

        postgresQuery<{
          total_audit_records: string;
          total_denied_events: string;
          total_downloads: string;
          total_uploads: string;
        }>(`
          SELECT
            COUNT(*) AS total_audit_records,
            COUNT(*) FILTER (WHERE status = 'DENIED') AS total_denied_events,
            COUNT(*) FILTER (WHERE action = 'DOCUMENT_DOWNLOAD') AS total_downloads,
            COUNT(*) FILTER (WHERE action = 'DOCUMENT_UPLOAD') AS total_uploads
          FROM audit_logs
        `),

        postgresQuery<{
          total_users: string;
          active_users: string;
        }>(`
          SELECT
            COUNT(*) AS total_users,
            COUNT(*) FILTER (WHERE is_active = 1) AS active_users
          FROM users
        `),
      ]);

      const doc = docResult.rows[0];
      const audit = auditResult.rows[0];
      const users = userResult.rows[0];

      res.json({
        metrics: {
          documents: {
            total_documents: Number(doc.total_documents),
            total_storage_bytes: Number(doc.total_storage_bytes),
          },
          audit: {
            total_audit_records: Number(audit.total_audit_records),
            total_denied_events: Number(audit.total_denied_events),
            total_downloads: Number(audit.total_downloads),
            total_uploads: Number(audit.total_uploads),
          },
          users: {
            total_users: Number(users.total_users),
            active_users: Number(users.active_users),
          },
        },
      });
    } catch (err: unknown) {
      console.error('[Admin] Could not retrieve metrics:', err);
      res.status(500).json({ error: 'Unable to retrieve system metrics' });
    }
  },
);

adminRouter.post(
  '/users/:id/toggle',
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const userResult = await postgresQuery<{
        id: string;
        email: string;
        name: string;
        role: 'admin' | 'owner' | 'viewer';
        is_active: number;
      }>(
        'SELECT id, email, name, role, is_active FROM users WHERE id = $1',
        [req.params.id],
      );

      const user = userResult.rows[0];

      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      if (user.id === req.user!.id) {
        res.status(400).json({
          error: 'You cannot deactivate or reactivate your own account here',
        });
        return;
      }

      const newStatus = user.is_active === 1 ? 0 : 1;

      const updatedResult = await postgresQuery<{
        id: string;
        email: string;
        name: string;
        role: 'admin' | 'owner' | 'viewer';
        is_active: number;
      }>(
        `UPDATE users
         SET is_active = $1
         WHERE id = $2
         RETURNING id, email, name, role, is_active`,
        [newStatus, user.id],
      );

      const ipHeader = req.headers['x-forwarded-for'];
      const ipAddress = (
        typeof ipHeader === 'string' ? ipHeader.split(',')[0].trim() : undefined
      ) || req.socket.remoteAddress || '127.0.0.1';

      await PgAuditService.recordEvent({
        actorId: req.user!.id,
        actorEmail: req.user!.email,
        actorRole: req.user!.role,
        action: newStatus === 0
          ? 'USER_ACCOUNT_DEACTIVATED'
          : 'USER_ACCOUNT_ACTIVATED',
        targetType: 'USER',
        targetId: user.id,
        targetName: user.email,
        status: 'SUCCESS',
        details: { previousStatus: user.is_active, newStatus },
        ipAddress,
        userAgent: req.headers['user-agent'] || 'client',
      });

      res.json({ success: true, user: updatedResult.rows[0] });
    } catch (err: unknown) {
      console.error('[Admin] User status update failed:', err);
      res.status(500).json({ error: 'Unable to update user status' });
    }
  },
);