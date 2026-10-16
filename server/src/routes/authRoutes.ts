import { Router, Response } from 'express';
import { z } from 'zod';
import { AuthService } from '../services/authService';
import { authenticate, AuthenticatedRequest } from '../middlewares/authMiddleware';

export const authRouter = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

/**
 * POST /api/auth/login
 * Public endpoint for user authentication
 */
authRouter.post('/login', (req, res: Response) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Validation failed', details: parsed.error.issues });
      return;
    }

    const ipAddress = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'client';

    const result = AuthService.login(parsed.data.email, parsed.data.password, ipAddress, userAgent);
    res.json(result);
  } catch (err: any) {
    res.status(401).json({ error: err.message, code: 'AUTH_FAILED' });
  }
});

/**
 * GET /api/auth/me
 * Returns current authenticated user profile
 */
authRouter.get('/me', authenticate, (req: AuthenticatedRequest, res: Response) => {
  res.json({ user: req.user });
});

/**
 * GET /api/auth/users
 * Returns list of system users (for selecting named recipients when sharing)
 */
authRouter.get('/users', authenticate, (req: AuthenticatedRequest, res: Response) => {
  const users = AuthService.listUsers();
  res.json({ users });
});
