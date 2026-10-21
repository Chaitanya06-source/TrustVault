import { Router, Response } from 'express';
import { z } from 'zod';
import { PgAuthService } from '../services/authService.pg';
import {
  authenticate,
  AuthenticatedRequest,
} from '../middlewares/authMiddleware';

export const authRouter = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

authRouter.post('/login', async (req, res: Response): Promise<void> => {
  const parsed = loginSchema.safeParse(req.body);

  if (!parsed.success) {
    res.status(400).json({
      error: 'Validation failed',
      details: parsed.error.issues,
    });
    return;
  }

  try {
    const result = await PgAuthService.login(
      parsed.data.email,
      parsed.data.password,
    );
    res.json(result);
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : 'Login failed';

    if (message === 'Account has been deactivated') {
      res.status(403).json({
        error: message,
        code: 'ACCOUNT_DEACTIVATED',
      });
      return;
    }

    if (message === 'Invalid credentials') {
      res.status(401).json({
        error: message,
        code: 'AUTH_FAILED',
      });
      return;
    }

    console.error('[Auth] Login failed:', message);
    res.status(500).json({
      error: 'Unable to log in at this time',
      code: 'AUTH_ERROR',
    });
  }
});

authRouter.get(
  '/me',
  authenticate,
  (req: AuthenticatedRequest, res: Response): void => {
    res.json({ user: req.user });
  },
);

authRouter.get(
  '/users',
  authenticate,
  async (_req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const users = await PgAuthService.listUsers();
      res.json({ users });
    } catch (err: unknown) {
      console.error('[Auth] Could not list users:', err);
      res.status(500).json({
        error: 'Unable to retrieve users',
        code: 'USERS_FETCH_FAILED',
      });
    }
  },
);