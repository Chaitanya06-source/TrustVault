import { Router, Response } from 'express';
import { authenticate, requireRole, AuthenticatedRequest } from '../legacyTestMiddlewares/authMiddleware';
import { AuditService } from '../services/auditService';
import { getDatabase } from '../db/database';

export const adminRouter = Router();

adminRouter.use(authenticate);
adminRouter.use(requireRole('admin'));

/**
 * GET /api/admin/alerts
 * Returns automated security alerts (e.g. denied download spikes, brute force probing)
 */
adminRouter.get('/alerts', (req: AuthenticatedRequest, res: Response) => {
  try {
    const alerts = AuditService.getSecurityAlerts();
    res.json({ alerts });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/admin/metrics
 * System-wide document activity and security health metrics.
 * Note: Admin sees structural counts without inspecting confidential file bytes.
 */
adminRouter.get('/metrics', (req: AuthenticatedRequest, res: Response) => {
  try {
    const db = getDatabase();

    const docStats = db.prepare(`
      SELECT
        COUNT(*) as total_documents,
        COALESCE(SUM(file_size_bytes), 0) as total_storage_bytes
      FROM documents
    `).get() as { total_documents: number; total_storage_bytes: number };

    const auditStats = db.prepare(`
      SELECT
        COUNT(*) as total_audit_records,
        SUM(CASE WHEN status = 'DENIED' THEN 1 ELSE 0 END) as total_denied_events,
        SUM(CASE WHEN action = 'DOCUMENT_DOWNLOAD' THEN 1 ELSE 0 END) as total_downloads,
        SUM(CASE WHEN action = 'DOCUMENT_UPLOAD' THEN 1 ELSE 0 END) as total_uploads
      FROM audit_logs
    `).get() as any;

    const userStats = db.prepare(`
      SELECT
        COUNT(*) as total_users,
        SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users
      FROM users
    `).get() as { total_users: number; active_users: number };

    res.json({
      metrics: {
        documents: docStats,
        audit: auditStats,
        users: userStats
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/admin/users/:id/toggle
 * Deactivates or activates a user.
 * Immediate effect: deactivated users cannot authenticate or use existing tokens.
 */
adminRouter.post('/users/:id/toggle', (req: AuthenticatedRequest, res: Response) => {
  try {
    const db = getDatabase();
    const user = db.prepare('SELECT id, email, name, role, is_active FROM users WHERE id = ?').get(req.params.id) as any;

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const newStatus = user.is_active === 1 ? 0 : 1;
    db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(newStatus, user.id);

    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    AuditService.recordEvent({
      actorId: req.user!.id,
      actorEmail: req.user!.email,
      actorRole: req.user!.role,
      action: newStatus === 0 ? 'USER_ACCOUNT_DEACTIVATED' : 'USER_ACCOUNT_ACTIVATED',
      targetType: 'USER',
      targetId: user.id,
      targetName: user.email,
      status: 'SUCCESS',
      details: { previousStatus: user.is_active, newStatus },
      ipAddress,
      userAgent
    });

    res.json({ success: true, user: { ...user, is_active: newStatus } });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});
