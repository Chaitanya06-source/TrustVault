import { v4 as uuidv4 } from 'uuid';
import { postgresQuery } from '../db/postgres';
import { PgAuditService } from './auditService.pg';

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

interface DocumentRow {
  id: string;
  title: string;
  owner_id: string;
}

interface UserRow {
  id: string;
  name: string;
  email: string;
}

export class PgPermissionService {
  public static async checkAccess(
    documentId: string,
    userId: string,
    requiredLevel: 'view' | 'edit' | 'owner'
  ): Promise<AccessCheckResult> {
    const docResult = await postgresQuery<DocumentRow>(
      'SELECT id, title, owner_id FROM documents WHERE id = $1',
      [documentId]
    );
    const doc = docResult.rows[0];

    if (!doc) {
      return { allowed: false, role: 'none', reason: 'Document does not exist' };
    }

    if (doc.owner_id === userId) {
      return { allowed: true, role: 'owner', documentTitle: doc.title };
    }

    if (requiredLevel === 'owner') {
      return {
        allowed: false,
        role: 'none',
        documentTitle: doc.title,
        reason: 'Only the document owner can perform this action'
      };
    }

    const grantResult = await postgresQuery<{ permission_level: PermissionLevel }>(
      `SELECT permission_level
       FROM document_permissions
       WHERE document_id = $1 AND user_id = $2`,
      [documentId, userId]
    );
    const grant = grantResult.rows[0];

    if (!grant) {
      return {
        allowed: false,
        role: 'none',
        documentTitle: doc.title,
        reason: 'Access denied: You have not been granted permission to this document'
      };
    }

    if (grant.permission_level === 'edit') {
      return { allowed: true, role: 'editor', documentTitle: doc.title };
    }

    if (requiredLevel === 'view') {
      return { allowed: true, role: 'viewer', documentTitle: doc.title };
    }

    return {
      allowed: false,
      role: 'viewer',
      documentTitle: doc.title,
      reason: 'Read-only access: Editing requires edit permission'
    };
  }

  public static async grantPermission(
    documentId: string,
    grantorId: string,
    grantorEmail: string,
    grantorRole: string,
    targetUserId: string,
    level: PermissionLevel,
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<PermissionGrant> {
    const docResult = await postgresQuery<DocumentRow>(
      'SELECT id, title, owner_id FROM documents WHERE id = $1',
      [documentId]
    );
    const doc = docResult.rows[0];

    if (!doc) throw new Error('Document not found');

    if (doc.owner_id !== grantorId) {
      await PgAuditService.recordEvent({
        actorId: grantorId,
        actorEmail: grantorEmail,
        actorRole: grantorRole,
        action: 'ACCESS_DENIED_GRANT',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: doc.title,
        status: 'DENIED',
        details: {
          reason: 'Non-owner attempted to grant document permissions',
          targetUserId,
          requestedLevel: level
        },
        ipAddress,
        userAgent
      });
      throw new Error('Only the document owner can grant permissions');
    }

    const targetResult = await postgresQuery<UserRow>(
      'SELECT id, name, email FROM users WHERE id = $1',
      [targetUserId]
    );
    const target = targetResult.rows[0];

    if (!target) throw new Error('Target user does not exist');
    if (targetUserId === grantorId) {
      throw new Error('Document owner already holds full permissions');
    }

    const existingResult = await postgresQuery<{ id: string }>(
      'SELECT id FROM document_permissions WHERE document_id = $1 AND user_id = $2',
      [documentId, targetUserId]
    );
    const existing = existingResult.rows[0];
    const grantId = existing?.id ?? uuidv4();
    const grantedAt = new Date().toISOString();

    await postgresQuery(
      `INSERT INTO document_permissions
         (id, document_id, user_id, permission_level, granted_by, granted_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (document_id, user_id)
       DO UPDATE SET
         permission_level = EXCLUDED.permission_level,
         granted_by = EXCLUDED.granted_by,
         granted_at = EXCLUDED.granted_at`,
      [grantId, documentId, targetUserId, level, grantorId, grantedAt]
    );

    const grantorResult = await postgresQuery<{ name: string }>(
      'SELECT name FROM users WHERE id = $1',
      [grantorId]
    );

    await PgAuditService.recordEvent({
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
        targetUserEmail: target.email,
        targetUserName: target.name,
        permissionLevel: level,
        isUpdate: !!existing
      },
      ipAddress,
      userAgent
    });

    return {
      id: grantId,
      document_id: documentId,
      user_id: targetUserId,
      user_name: target.name,
      user_email: target.email,
      permission_level: level,
      granted_by: grantorId,
      grantor_name: grantorResult.rows[0]?.name ?? 'Owner',
      granted_at: grantedAt
    };
  }

  public static async revokePermission(
    documentId: string,
    revokerId: string,
    revokerEmail: string,
    revokerRole: string,
    targetUserId: string,
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<void> {
    const docResult = await postgresQuery<DocumentRow>(
      'SELECT id, title, owner_id FROM documents WHERE id = $1',
      [documentId]
    );
    const doc = docResult.rows[0];

    if (!doc) throw new Error('Document not found');

    if (doc.owner_id !== revokerId) {
      await PgAuditService.recordEvent({
        actorId: revokerId,
        actorEmail: revokerEmail,
        actorRole: revokerRole,
        action: 'ACCESS_DENIED_REVOKE',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: doc.title,
        status: 'DENIED',
        details: {
          reason: 'Non-owner attempted to revoke permissions',
          targetUserId
        },
        ipAddress,
        userAgent
      });
      throw new Error('Only the document owner can revoke permissions');
    }

    const targetResult = await postgresQuery<UserRow>(
      'SELECT id, name, email FROM users WHERE id = $1',
      [targetUserId]
    );
    const target = targetResult.rows[0];

    const deleteResult = await postgresQuery(
      'DELETE FROM document_permissions WHERE document_id = $1 AND user_id = $2 RETURNING id',
      [documentId, targetUserId]
    );

    if (deleteResult.rowCount === 0) {
      throw new Error('User did not have active permissions to revoke');
    }

    await PgAuditService.recordEvent({
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
        targetUserEmail: target?.email ?? 'unknown',
        targetUserName: target?.name ?? 'unknown',
        immediateEffect: true
      },
      ipAddress,
      userAgent
    });
  }

  public static async listPermissions(
    documentId: string,
    requesterId: string
  ): Promise<PermissionGrant[]> {
    const docResult = await postgresQuery<{ id: string; owner_id: string }>(
      'SELECT id, owner_id FROM documents WHERE id = $1',
      [documentId]
    );
    const doc = docResult.rows[0];

    if (!doc) throw new Error('Document not found');
    if (doc.owner_id !== requesterId) {
      throw new Error('Only the document owner can view permissions');
    }

    const result = await postgresQuery<PermissionGrant>(
      `SELECT
         dp.id,
         dp.document_id,
         dp.user_id,
         u.name AS user_name,
         u.email AS user_email,
         dp.permission_level,
         dp.granted_by,
         gu.name AS grantor_name,
         dp.granted_at
       FROM document_permissions dp
       JOIN users u ON dp.user_id = u.id
       JOIN users gu ON dp.granted_by = gu.id
       WHERE dp.document_id = $1
       ORDER BY dp.granted_at DESC`,
      [documentId]
    );

    return result.rows;
  }
}