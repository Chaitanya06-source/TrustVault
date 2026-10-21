import { Request, Response, NextFunction } from 'express';
import { AuthService, AuthTokenPayload } from '../services/authService';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: 'admin' | 'owner' | 'viewer';
    name: string;
  };
}

export function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  try {
    let token: string | undefined;

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (req.query && typeof req.query.token === 'string') {
      token = req.query.token;
    }

    if (!token) {
      res.status(401).json({
        error: 'Authentication required: No bearer token provided',
        code: 'UNAUTHENTICATED'
      });
      return;
    }

    const payload = AuthService.verifyToken(token);

    // Verify user is still active in the database (handles immediate account deactivation)
    const activeUser = AuthService.getUserById(payload.userId);
    if (!activeUser || activeUser.is_active !== 1) {
      res.status(401).json({
        error: 'Account is deactivated or does not exist',
        code: 'ACCOUNT_DEACTIVATED'
      });
      return;
    }

    req.user = {
      id: activeUser.id,
      email: activeUser.email,
      role: activeUser.role,
      name: activeUser.name
    };

    next();
  } catch (err: any) {
    res.status(401).json({
      error: 'Invalid or expired authentication token',
      code: 'TOKEN_INVALID',
      details: err.message
    });
  }
}

export function requireRole(...allowedRoles: Array<'admin' | 'owner' | 'viewer'>) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthenticated', code: 'UNAUTHENTICATED' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: `Forbidden: Action requires role [${allowedRoles.join(', ')}], current role is '${req.user.role}'`,
        code: 'FORBIDDEN_ROLE'
      });
      return;
    }

    next();
  };
}
