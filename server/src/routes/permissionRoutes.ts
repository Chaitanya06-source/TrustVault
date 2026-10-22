import { Router, Response } from 'express';
import { z } from 'zod';
import { authenticate, AuthenticatedRequest } from '../middlewares/authMiddleware';
import { PgPermissionService } from '../services/permissionService.pg';

export const permissionRouter = Router({ mergeParams: true });

permissionRouter.use(authenticate);

const grantSchema = z.object({
  userId: z.string().uuid(),
  permissionLevel: z.enum(['view', 'edit'])
});

permissionRouter.get(
  '/:id/permissions',
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const grants = await PgPermissionService.listPermissions(
        req.params.id,
        req.user!.id
      );

      res.json({ permissions: grants });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unable to list permissions';
      const status = message === 'Document not found' ? 404 : 403;

      res.status(status).json({
        error: message,
        code: 'FORBIDDEN'
      });
    }
  }
);

permissionRouter.post(
  '/:id/permissions',
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const parsed = grantSchema.safeParse(req.body);

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

      const grant = await PgPermissionService.grantPermission(
        req.params.id,
        req.user!.id,
        req.user!.email,
        req.user!.role,
        parsed.data.userId,
        parsed.data.permissionLevel,
        ipAddress,
        userAgent
      );

      res.status(201).json({
        permission: grant,
        message: 'Permission granted successfully'
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unable to grant permission';
      const status = message === 'Document not found' ? 404 : 403;

      res.status(status).json({
        error: message,
        code: 'GRANT_FAILED'
      });
    }
  }
);

permissionRouter.delete(
  '/:id/permissions/:userId',
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const ipAddress =
        (req.headers['x-forwarded-for'] as string) ||
        req.socket.remoteAddress ||
        '127.0.0.1';

      const userAgent = req.headers['user-agent'] || 'client';

      await PgPermissionService.revokePermission(
        req.params.id,
        req.user!.id,
        req.user!.email,
        req.user!.role,
        req.params.userId,
        ipAddress,
        userAgent
      );

      res.json({
        success: true,
        message: 'Permission revoked with immediate effect'
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unable to revoke permission';
      const status = message === 'Document not found' ? 404 : 403;

      res.status(status).json({
        error: message,
        code: 'REVOKE_FAILED'
      });
    }
  }
);