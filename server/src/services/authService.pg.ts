import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { postgresQuery } from '../db/postgres';
import { CONFIG } from '../config';

export type UserRole = 'admin' | 'owner' | 'viewer';

export interface PgUserRecord {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  role: UserRole;
  is_active: number;
  created_at: string;
}

export interface PgAuthTokenPayload {
  userId: string;
  email: string;
  role: UserRole;
  name: string;
}

type SafeUser = Omit<PgUserRecord, 'password_hash'>;

export class PgAuthService {
  public static hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${derivedKey}`;
  }

  public static verifyPassword(
    password: string,
    storedHash: string,
  ): boolean {
    const parts = storedHash.split(':');
    if (parts.length !== 2) return false;

    const [salt, expectedKeyHex] = parts;

    if (!/^[a-f0-9]{32}$/i.test(salt)) return false;
    if (!/^[a-f0-9]{128}$/i.test(expectedKeyHex)) return false;

    const derivedKey = crypto.scryptSync(password, salt, 64);
    const expectedKey = Buffer.from(expectedKeyHex, 'hex');

    return crypto.timingSafeEqual(derivedKey, expectedKey);
  }

  public static generateToken(payload: PgAuthTokenPayload): string {
    return jwt.sign(payload, CONFIG.JWT_SECRET, {
      expiresIn: '8h',
    });
  }

  public static verifyToken(token: string): PgAuthTokenPayload {
    const payload = jwt.verify(token, CONFIG.JWT_SECRET);

    if (
      typeof payload === 'string' ||
      !payload.userId ||
      !payload.email ||
      !payload.role ||
      !payload.name
    ) {
      throw new Error('Invalid authentication token payload');
    }

    return payload as PgAuthTokenPayload;
  }

  public static async login(
    email: string,
    plainPassword: string,
  ): Promise<{ token: string; user: SafeUser }> {
    const normalizedEmail = email.trim().toLowerCase();

    const result = await postgresQuery<PgUserRecord>(
      `SELECT id, email, name, password_hash, role, is_active, created_at
       FROM users
       WHERE LOWER(email) = $1
       LIMIT 1`,
      [normalizedEmail],
    );

    const user = result.rows[0];

    const dummyHash =
      '00000000000000000000000000000000:' +
      '0000000000000000000000000000000000000000000000000000000000000000' +
      '0000000000000000000000000000000000000000000000000000000000000000';

    const passwordValid = this.verifyPassword(
      plainPassword,
      user?.password_hash ?? dummyHash,
    );

    if (!user || !passwordValid) {
      throw new Error('Invalid credentials');
    }

    if (user.is_active !== 1) {
      throw new Error('Account has been deactivated');
    }

    const token = this.generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
    });

    const { password_hash: _passwordHash, ...safeUser } = user;

    return { token, user: safeUser };
  }

  public static async getUserById(
    userId: string,
  ): Promise<SafeUser | null> {
    const result = await postgresQuery<SafeUser>(
      `SELECT id, email, name, role, is_active, created_at
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [userId],
    );

    return result.rows[0] ?? null;
  }

  public static async listUsers(): Promise<SafeUser[]> {
    const result = await postgresQuery<SafeUser>(
      `SELECT id, email, name, role, is_active, created_at
       FROM users
       WHERE is_active = 1
       ORDER BY name ASC`,
    );

    return result.rows;
  }
}