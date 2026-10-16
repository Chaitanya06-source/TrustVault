import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../db/database';
import { CONFIG } from '../config';
import { AuditService } from './auditService';

export interface UserRecord {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  role: 'admin' | 'owner' | 'viewer';
  is_active: number;
  created_at: string;
}

export interface AuthTokenPayload {
  userId: string;
  email: string;
  role: 'admin' | 'owner' | 'viewer';
  name: string;
}

export class AuthService {
  /**
   * Hashes a password using crypto.scrypt with a unique cryptographically random salt.
   * Format: salt:derivedKeyHex
   */
  public static hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${derivedKey}`;
  }

  /**
   * Verifies password against stored hash using constant-time comparison to prevent timing attacks.
   */
  public static verifyPassword(password: string, storedHash: string): boolean {
    const parts = storedHash.split(':');
    if (parts.length !== 2) return false;

    const [salt, expectedKeyHex] = parts;
    const derivedKey = crypto.scryptSync(password, salt, 64);
    const expectedKey = Buffer.from(expectedKeyHex, 'hex');

    if (derivedKey.length !== expectedKey.length) {
      return false;
    }

    return crypto.timingSafeEqual(derivedKey, expectedKey);
  }

  /**
   * Generates a signed JWT with expiration.
   */
  public static generateToken(payload: AuthTokenPayload): string {
    return jwt.sign(payload, CONFIG.JWT_SECRET, {
      expiresIn: '8h'
    });
  }

  /**
   * Verifies a JWT token signature and returns the payload.
   */
  public static verifyToken(token: string): AuthTokenPayload {
    return jwt.verify(token, CONFIG.JWT_SECRET) as AuthTokenPayload;
  }

  /**
   * Authenticates user credentials with constant-time password verification
   * and records success/failure in the immutable audit trail.
   */
  public static login(
    email: string,
    plainPassword: string,
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): { token: string; user: Omit<UserRecord, 'password_hash'> } {
    const db = getDatabase();
    const normalizedEmail = email.trim().toLowerCase();

    const user = db
      .prepare('SELECT * FROM users WHERE LOWER(email) = ?')
      .get(normalizedEmail) as UserRecord | undefined;

    // Defense against timing attack user enumeration:
    // If user does not exist, compute a dummy scrypt verification so response time is identical
    const dummyHash = '00000000000000000000000000000000:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
    const hashToVerify = user ? user.password_hash : dummyHash;
    const passwordValid = this.verifyPassword(plainPassword, hashToVerify);

    if (!user || !passwordValid) {
      // Record failed authentication attempt into audit ledger
      AuditService.recordEvent({
        actorId: user ? user.id : 'unknown',
        actorEmail: normalizedEmail,
        actorRole: user ? user.role : 'anonymous',
        action: 'AUTH_LOGIN_FAILURE',
        targetType: 'AUTH',
        targetId: user ? user.id : null,
        targetName: normalizedEmail,
        status: 'DENIED',
        details: { reason: 'Invalid email or password' },
        ipAddress,
        userAgent
      });

      throw new Error('Invalid credentials');
    }

    if (user.is_active !== 1) {
      AuditService.recordEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        action: 'AUTH_LOGIN_DISABLED_ACCOUNT',
        targetType: 'AUTH',
        targetId: user.id,
        targetName: user.email,
        status: 'DENIED',
        details: { reason: 'Account has been deactivated' },
        ipAddress,
        userAgent
      });
      throw new Error('Account has been deactivated');
    }

    const tokenPayload: AuthTokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      name: user.name
    };

    const token = this.generateToken(tokenPayload);

    // Audit successful login
    AuditService.recordEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      action: 'AUTH_LOGIN_SUCCESS',
      targetType: 'AUTH',
      targetId: user.id,
      targetName: user.email,
      status: 'SUCCESS',
      details: { role: user.role },
      ipAddress,
      userAgent
    });

    const { password_hash, ...safeUser } = user;
    return { token, user: safeUser };
  }

  /**
   * Fetches active user by ID and verifies they are still active in the database.
   */
  public static getUserById(userId: string): Omit<UserRecord, 'password_hash'> | null {
    const db = getDatabase();
    const user = db
      .prepare('SELECT id, email, name, role, is_active, created_at FROM users WHERE id = ?')
      .get(userId) as Omit<UserRecord, 'password_hash'> | undefined;

    return user || null;
  }

  /**
   * Lists all users in the system (useful for granting permissions).
   */
  public static listUsers(): Array<Omit<UserRecord, 'password_hash'>> {
    const db = getDatabase();
    return db
      .prepare('SELECT id, email, name, role, is_active, created_at FROM users WHERE is_active = 1 ORDER BY name ASC')
      .all() as Array<Omit<UserRecord, 'password_hash'>>;
  }
}
