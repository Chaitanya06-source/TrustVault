import express from 'express';
import request from 'supertest';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { listUsers } = vi.hoisted(() => ({
  listUsers: vi.fn(),
}));

vi.mock('../src/services/authService.pg', () => ({
  PgAuthService: {
    listUsers,
  },
}));

// Keep this route test independent of the real JWT/database layer while
// preserving the route's middleware chain and testing that the route actually
// installs a role restriction. If requireRole is removed from /users, the
// viewer case below receives 200 and fails.
vi.mock('../src/middlewares/authMiddleware', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    const role = String(req.headers['x-test-role'] || 'viewer');
    req.user = {
      id: `test-${role}`,
      email: `${role}@example.test`,
      role,
      name: role,
    };
    next();
  },
  requireRole: (...allowedRoles: string[]) => (req: any, res: any, next: any) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  },
}));

import { authRouter } from '../src/routes/authRoutes';

const app = express();
app.use('/api/auth', authRouter);

describe('GET /api/auth/users authorization', () => {
  beforeEach(() => {
    listUsers.mockReset();
    listUsers.mockResolvedValue([{ id: 'recipient-1', email: 'person@example.test' }]);
  });

  it('denies viewers so external/viewer accounts cannot enumerate internal email addresses', async () => {
    const response = await request(app)
      .get('/api/auth/users')
      .set('x-test-role', 'viewer');

    expect(response.status).toBe(403);
    expect(listUsers).not.toHaveBeenCalled();
  });

  it('allows document owners to select named recipients', async () => {
    const response = await request(app)
      .get('/api/auth/users')
      .set('x-test-role', 'owner');

    expect(response.status).toBe(200);
    expect(response.body.users).toHaveLength(1);
    expect(listUsers).toHaveBeenCalledTimes(1);
  });

  it('allows administrators to list users', async () => {
    const response = await request(app)
      .get('/api/auth/users')
      .set('x-test-role', 'admin');

    expect(response.status).toBe(200);
    expect(listUsers).toHaveBeenCalledTimes(1);
  });
});
