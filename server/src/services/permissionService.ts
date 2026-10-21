import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../db/database';
import { AuditService } from './auditService';

export type PermissionLevel = 'view' | 'edit';
export type AccessRole = 'owner' | 'editor' | 'viewer' | 'none';

export interface AccessCheckResult {
  allowed: boolean;
  role: AccessRole;
  documentTitle?: string;
  reason?: string;
}

export interface PermissionGrant {
  id: string;
  document_id: string;
  user_id: string;
  user_name: string;
  user_email: string;
  permission_level: PermissionLevel;
  granted_by: string;
  grantor_name: string;
  granted_at: string;
}

export class PermissionService {
  /**
   * Evaluates document access permissions in real-time.
   * Every single read, write, download, or metadata access queries this function.
   * There are NO cached bypasses or long-lived static tokens.
   */
  public static checkAccess(
    documentId: string,
    userId: string,
    requiredLevel: 'view' | 'edit' | 'owner'
  ): AccessCheckResult {
    const db = getDatabase();

    // 1. Fetch document existence and owner
    const doc = db
      .prepare('SELECT id, title, owner_id FROM documents WHERE id = ?')
      .get(documentId) as { id: string; title: string; owner_id: string } | undefined;

    if (!doc) {
      return {
        allowed: false,
        role: 'none',
        reason: 'Document does not exist'
      };
    }

    // 2. Owner check (owner always has full control)
    if (doc.owner_id === userId) {
      return {
        allowed: true,
        role: 'owner',
        documentTitle: doc.title
      };
    }

    // If 'owner' level was required, non-owners cannot proceed
    if (requiredLevel === 'owner') {
      return {
        allowed: false,
        role: 'none',
        documentTitle: doc.title,
        reason: 'Only the document owner can perform this action'
      };
    }

    // 3. Query direct named grants in document_permissions table
    const grant = db
      .prepare('SELECT permission_level FROM document_permissions WHERE document_id = ? AND user_id = ?')
      .get(documentId, userId) as { permission_level: PermissionLevel } | undefined;

    if (!grant) {
      return {
        allowed: false,
        role: 'none',
        documentTitle: doc.title,
        reason: 'Access denied: You have not been granted permission to this document'
      };
    }

    // 4. Role evaluation
    if (grant.permission_level === 'edit') {
      return {
        allowed: true,
        role: 'editor',
        documentTitle: doc.title
      };
    }

    if (grant.permission_level === 'view') {
      if (requiredLevel === 'view') {
        return {
          allowed: true,
          role: 'viewer',
          documentTitle: doc.title
        };
      }
      return {
        allowed: false,
        role: 'viewer',
        documentTitle: doc.title,
        reason: 'Read-only access: Editing requires edit permission'
      };
    }

    return {
      allowed: false,
      role: 'none',
      documentTitle: doc.title,
      reason: 'Access denied'
    };
  }

  /**
   * Grants a named user 'view' or 'edit' access to a document.
   * Only the document owner can grant permissions.
   */
  public static grantPermission(
    documentId: string,
    grantorId: string,
    grantorEmail: string,
    grantorRole: string,
    targetUserId: string,
    level: PermissionLevel,
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): PermissionGrant {
    const db = getDatabase();

    // 1. Verify grantor is owner
    const doc = db
      .prepare('SELECT id, title, owner_id FROM documents WHERE id = ?')
      .get(documentId) as { id: string; title: string; owner_id: string } | undefined;

    if (!doc) {
      throw new Error('Document not found');
    }

    if (doc.owner_id !== grantorId) {
      AuditService.recordEvent({
        actorId: grantorId,
        actorEmail: grantorEmail,
        actorRole: grantorRole,
        action: 'ACCESS_DENIED_GRANT',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: doc.title,
        status: 'DENIED',
        details: { reason: 'Non-owner attempted to grant document permissions', targetUserId, requestedLevel: level },
        ipAddress,
        userAgent
      });
      throw new Error('Only the document owner can grant permissions');
    }

    // 2. Verify target user exists
    const targetUser = db
      .prepare('SELECT id, name, email FROM users WHERE id = ?')
      .get(targetUserId) as { id: string; name: string; email: string } | undefined;

    if (!targetUser) {
      throw new Error('Target user does not exist');
    }

    if (targetUserId === grantorId) {
      throw new Error('Document owner already holds full permissions');
    }

    // 3. Upsert permission grant
    const existing = db
      .prepare('SELECT id FROM document_permissions WHERE document_id = ? AND user_id = ?')
      .get(documentId, targetUserId) as { id: string } | undefined;

    const grantId = existing ? existing.id : uuidv4();
    const grantedAt = new Date().toISOString();

    if (existing) {
      db.prepare(`
        UPDATE document_permissions
        SET permission_level = ?, granted_by = ?, granted_at = ?
        WHERE id = ?
      `).run(level, grantorId, grantedAt, grantId);
    } else {
      db.prepare(`
        INSERT INTO document_permissions (id, document_id, user_id, permission_level, granted_by, granted_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(grantId, documentId, targetUserId, level, grantorId, grantedAt);
    }

    // 4. Record in tamper-evident audit ledger
    AuditService.recordEvent({
      actorId: grantorId,
      actorEmail: grantorEmail,
      actorRole: grantorRole,
      action: 'PERMISSION_GRANTED',
      targetType: 'PERMISSION',
      targetId: documentId,
      targetName: doc.title,
      status: 'SUCCESS',
      details: {
        targetUserId,
        targetUserEmail: targetUser.email,
        targetUserName: targetUser.name,
        permissionLevel: level,
        isUpdate: !!existing
      },
      ipAddress,
      userAgent
    });

    const grantorUser = db.prepare('SELECT name FROM users WHERE id = ?').get(grantorId) as { name: string } | undefined;

    return {
      id: grantId,
      document_id: documentId,
      user_id: targetUserId,
      user_name: targetUser.name,
      user_email: targetUser.email,
      permission_level: level,
      granted_by: grantorId,
      grantor_name: grantorUser ? grantorUser.name : 'Owner',
      granted_at: grantedAt
    };
  }

  /**
   * Revokes a user's access immediately.
   * Takes effect on the very next request.
   */
  public static revokePermission(
    documentId: string,
    revokerId: string,
    revokerEmail: string,
    revokerRole: string,
    targetUserId: string,
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): void {
    const db = getDatabase();

    // 1. Verify revoker is owner
    const doc = db
      .prepare('SELECT id, title, owner_id FROM documents WHERE id = ?')
      .get(documentId) as { id: string; title: string; owner_id: string } | undefined;

    if (!doc) {
      throw new Error('Document not found');
    }

    if (doc.owner_id !== revokerId) {
      AuditService.recordEvent({
        actorId: revokerId,
        actorEmail: revokerEmail,
        actorRole: revokerRole,
        action: 'ACCESS_DENIED_REVOKE',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: doc.title,
        status: 'DENIED',
        details: { reason: 'Non-owner attempted to revoke permissions', targetUserId },
        ipAddress,
        userAgent
      });
      throw new Error('Only the document owner can revoke permissions');
    }

    const targetUser = db
      .prepare('SELECT id, name, email FROM users WHERE id = ?')
      .get(targetUserId) as { id: string; name: string; email: string } | undefined;

    // 2. Delete the permission grant
    const result = db
      .prepare('DELETE FROM document_permissions WHERE document_id = ? AND user_id = ?')
      .run(documentId, targetUserId);

    if (result.changes === 0) {
      throw new Error('User did not have active permissions to revoke');
    }

    // 3. Record in audit trail
    AuditService.recordEvent({
      actorId: revokerId,
      actorEmail: revokerEmail,
      actorRole: revokerRole,
      action: 'PERMISSION_REVOKED',
      targetType: 'PERMISSION',
      targetId: documentId,
      targetName: doc.title,
      status: 'SUCCESS',
      details: {
        targetUserId,
        targetUserEmail: targetUser ? targetUser.email : 'unknown',
        targetUserName: targetUser ? targetUser.name : 'unknown',
        immediateEffect: true
      },
      ipAddress,
      userAgent
    });
  }

  /**
   * Lists all users who currently have active permission to a document.
   */
  public static listPermissions(documentId: string, requesterId: string): PermissionGrant[] {
    const db = getDatabase();

    // Only owner can inspect full permissions list
    const doc = db
      .prepare('SELECT id, owner_id FROM documents WHERE id = ?')
      .get(documentId) as { id: string; owner_id: string } | undefined;

    if (!doc) {
      throw new Error('Document not found');
    }

    if (doc.owner_id !== requesterId) {
      throw new Error('Only the document owner can view permissions');
    }

    return db.prepare(`
      SELECT
        dp.id,
        dp.document_id,
        dp.user_id,
        u.name as user_name,
        u.email as user_email,
        dp.permission_level,
        dp.granted_by,
        gu.name as grantor_name,
        dp.granted_at
      FROM document_permissions dp
      JOIN users u ON dp.user_id = u.id
      JOIN users gu ON dp.granted_by = gu.id
      WHERE dp.document_id = ?
      ORDER BY dp.granted_at DESC
    `).all(documentId) as unknown as PermissionGrant[];
  }
}
