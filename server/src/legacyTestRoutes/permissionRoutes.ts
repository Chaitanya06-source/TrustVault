import { Router, Response } from 'express';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../legacyTestMiddlewares/authMiddleware';
import { PermissionService } from '../services/permissionService';

export const permissionRouter = Router({ mergeParams: true });

permissionRouter.use(authenticate);

const grantSchema = z.object({
  userId: z.string().uuid(),
  permissionLevel: z.enum(['view', 'edit'])
});

/**
 * GET /api/documents/:id/permissions
 * Lists current active permissions for a document. Requires document owner.
 */
permissionRouter.get('/:id/permissions', (req: AuthenticatedRequest, res: Response) => {
  try {
    const grants = PermissionService.listPermissions(req.params.id, req.user!.id);
    res.json({ permissions: grants });
  } catch (err: any) {
    res.status(403).json({ error: err.message, code: 'FORBIDDEN' });
  }
});

/**
 * POST /api/documents/:id/permissions
 * Grants 'view' or 'edit' permission to a named user. Requires document owner.
 */
permissionRouter.post('/:id/permissions', (req: AuthenticatedRequest, res: Response) => {
  try {
    const parsed = grantSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Validation failed', details: parsed.error.issues });
      return;
    }

    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const grant = PermissionService.grantPermission(
      req.params.id,
      req.user!.id,
      req.user!.email,
      req.user!.role,
      parsed.data.userId,
      parsed.data.permissionLevel,
      ipAddress,
      userAgent
    );

    res.status(201).json({ permission: grant, message: 'Permission granted successfully' });
  } catch (err: any) {
    res.status(403).json({ error: err.message, code: 'GRANT_FAILED' });
  }
});

/**
 * DELETE /api/documents/:id/permissions/:userId
 * Revokes permission with IMMEDIATE EFFECT. Requires document owner.
 */
permissionRouter.delete('/:id/permissions/:userId', (req: AuthenticatedRequest, res: Response) => {
  try {
    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    PermissionService.revokePermission(
      req.params.id,
      req.user!.id,
      req.user!.email,
      req.user!.role,
      req.params.userId,
      ipAddress,
      userAgent
    );

    res.json({ success: true, message: 'Permission revoked with immediate effect' });
  } catch (err: any) {
    res.status(403).json({ error: err.message, code: 'REVOKE_FAILED' });
  }
});
