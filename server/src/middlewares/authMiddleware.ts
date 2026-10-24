import { Request, Response, NextFunction } from 'express';
import { PgAuthService } from '../services/authService.pg';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: 'admin' | 'owner' | 'viewer';
    name: string;
  };
}

export async function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    let token: string | undefined;
    const authHeader = req.headers.authorization;

    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }

    if (!token) {
      res.status(401).json({
        error: 'Authentication required: No bearer token provided',
        code: 'UNAUTHENTICATED',
      });
      return;
    }

    const payload = PgAuthService.verifyToken(token);
    const activeUser = await PgAuthService.getUserById(payload.userId);

    if (!activeUser || activeUser.is_active !== 1) {
      res.status(401).json({
        error: 'Account is deactivated or does not exist',
        code: 'ACCOUNT_DEACTIVATED',
      });
      return;
    }

    req.user = {
      id: activeUser.id,
      email: activeUser.email,
      role: activeUser.role,
      name: activeUser.name,
    };

    next();
  } catch {
    res.status(401).json({
      error: 'Invalid or expired authentication token',
      code: 'TOKEN_INVALID',
    });
  }
}

export function requireRole(
  ...allowedRoles: Array<'admin' | 'owner' | 'viewer'>
) {
  return (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): void => {
    if (!req.user) {
      res.status(401).json({
        error: 'Authentication required',
        code: 'UNAUTHENTICATED',
      });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: 'Insufficient permissions',
        code: 'FORBIDDEN',
      });
      return;
    }

    next();
  };
}