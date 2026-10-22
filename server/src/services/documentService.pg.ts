
import { v4 as uuidv4 } from 'uuid';
import { postgresQuery } from '../db/postgres';
import { FileService } from './fileService';
import { PgPermissionService, AccessRole } from './permissionService.pg';
import { PgAuditService } from './auditService.pg';
import { SupabaseFileService } from './supabaseFileService';

export interface DocumentRecord {
  id: string;
  title: string;
  description: string | null;
  category: string;
  classification: string;
  owner_id: string;
  owner_name?: string;
  owner_email?: string;
  storage_path: string;
  original_filename: string;
  file_size_bytes: number;
  mime_type: string;
  checksum_sha256: string;
  version: number;
  created_at: string;
  updated_at: string;
  user_permission?: AccessRole;
}

type Requester = {
  id: string;
  email: string;
  role: string;
};

function httpError(message: string, statusCode: number): Error {
  const error = new Error(message) as Error & { statusCode: number };
  error.statusCode = statusCode;
  return error;
}

export class DocumentService {
  public static async uploadDocument(
    owner: Requester,
    file: {
      originalname: string;
      buffer: Buffer;
      size: number;
    },
    metadata: {
      title: string;
      description?: string;
      category: string;
      classification?: string;
    },
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<DocumentRecord> {
    const validation = FileService.validateUpload(file);

    if (
      !validation.valid ||
      !validation.sanitizedFilename ||
      !validation.verifiedMime
    ) {
      await PgAuditService.recordEvent({
        actorId: owner.id,
        actorEmail: owner.email,
        actorRole: owner.role,
        action: 'DOCUMENT_UPLOAD_REJECTED',
        targetType: 'DOCUMENT',
        status: 'DENIED',
        details: {
          filename: file.originalname,
          size: file.size,
          reason: validation.error
        },
        ipAddress,
        userAgent
      });

      throw httpError(
        `File validation failed: ${validation.error}`,
        400
      );
    }

    const stored = await SupabaseFileService.saveToVault(
      file.buffer,
      validation.sanitizedFilename,
      validation.verifiedMime
    );

    const id = uuidv4();
    const now = new Date().toISOString();
    const title = metadata.title.trim();
    const description = metadata.description?.trim() || null;
    const category = metadata.category.trim();
    const classification = metadata.classification || 'Confidential';

    try {
      await postgresQuery(
        `INSERT INTO documents (
          id, title, description, category, classification, owner_id,
          storage_path, original_filename, file_size_bytes, mime_type,
          checksum_sha256, version, created_at, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [
          id,
          title,
          description,
          category,
          classification,
          owner.id,
          stored.storagePath,
          stored.originalFilename,
          stored.fileSizeBytes,
          stored.mimeType,
          stored.checksumSha256,
          1,
          now,
          now
        ]
      );
    } catch (error) {
      try {
        await SupabaseFileService.deleteFromVault(stored.storagePath);
      } catch (cleanupError) {
        console.error(
          'Failed to clean up Supabase file after database insert failure:',
          cleanupError
        );
      }

      throw error;
    }

    await PgAuditService.recordEvent({
      actorId: owner.id,
      actorEmail: owner.email,
      actorRole: owner.role,
      action: 'DOCUMENT_UPLOAD',
      targetType: 'DOCUMENT',
      targetId: id,
      targetName: title,
      status: 'SUCCESS',
      details: {
        filename: stored.originalFilename,
        fileSize: stored.fileSizeBytes,
        mimeType: stored.mimeType,
        checksum: stored.checksumSha256,
        category,
        classification
      },
      ipAddress,
      userAgent
    });

    return {
      id,
      title,
      description,
      category,
      classification,
      owner_id: owner.id,
      storage_path: stored.storagePath,
      original_filename: stored.originalFilename,
      file_size_bytes: stored.fileSizeBytes,
      mime_type: stored.mimeType,
      checksum_sha256: stored.checksumSha256,
      version: 1,
      created_at: now,
      updated_at: now,
      user_permission: 'owner'
    };
  }

  public static async getDocumentById(
    documentId: string,
    requester: Requester,
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<DocumentRecord> {
    const access = await PgPermissionService.checkAccess(
      documentId,
      requester.id,
      'view'
    );

    if (!access.allowed) {
      await PgAuditService.recordEvent({
        actorId: requester.id,
        actorEmail: requester.email,
        actorRole: requester.role,
        action: 'ACCESS_DENIED_VIEW',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: access.documentTitle || 'Unknown Document',
        status: 'DENIED',
        details: { reason: access.reason },
        ipAddress,
        userAgent
      });

      throw httpError(access.reason || 'Access denied', 403);
    }

    const result = await postgresQuery<
      DocumentRecord & {
        owner_name: string;
        owner_email: string;
      }
    >(
      `SELECT d.*, u.name AS owner_name, u.email AS owner_email
       FROM documents d
       JOIN users u ON u.id = d.owner_id
       WHERE d.id = $1`,
      [documentId]
    );

    const doc = result.rows[0];

    if (!doc) {
      throw httpError('Document not found', 404);
    }

    doc.user_permission = access.role;
    return doc;
  }

  public static async getFileForDownload(
    documentId: string,
    requester: Requester,
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<{
    buffer: Buffer;
    filename: string;
    mimeType: string;
    fileSize: number;
    checksum: string;
  }> {
    const access = await PgPermissionService.checkAccess(
      documentId,
      requester.id,
      'view'
    );

    if (!access.allowed) {
      await PgAuditService.recordEvent({
        actorId: requester.id,
        actorEmail: requester.email,
        actorRole: requester.role,
        action: 'ACCESS_DENIED_DOWNLOAD',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: access.documentTitle || 'Unknown Document',
        status: 'DENIED',
        details: {
          reason: access.reason,
          attemptedDownload: true
        },
        ipAddress,
        userAgent
      });

      throw httpError(
        'Access denied: You do not have permission to download this document',
        403
      );
    }

    const result = await postgresQuery<DocumentRecord>(
      'SELECT * FROM documents WHERE id = $1',
      [documentId]
    );

    const doc = result.rows[0];

    if (!doc) {
      throw httpError('Document not found', 404);
    }

    // Fetch from private Supabase Storage only after permission checks.
    const buffer = await SupabaseFileService.getFileBuffer(
      doc.storage_path
    );

    await PgAuditService.recordEvent({
      actorId: requester.id,
      actorEmail: requester.email,
      actorRole: requester.role,
      action: 'DOCUMENT_DOWNLOAD',
      targetType: 'DOCUMENT',
      targetId: documentId,
      targetName: doc.title,
      status: 'SUCCESS',
      details: {
        filename: doc.original_filename,
        checksum: doc.checksum_sha256,
        fileSize: doc.file_size_bytes
      },
      ipAddress,
      userAgent
    });

    return {
      buffer,
      filename: doc.original_filename,
      mimeType: doc.mime_type,
      fileSize: Number(doc.file_size_bytes),
      checksum: doc.checksum_sha256
    };
  }

  public static async searchDocuments(
    requester: { id: string; role: string },
    filters: {
      query?: string;
      category?: string;
      ownerId?: string;
      fromDate?: string;
      toDate?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ documents: DocumentRecord[]; total: number }> {
    const clauses = ['(d.owner_id = $1 OR dp.user_id = $1)'];
    const params: unknown[] = [requester.id];

    const addFilter = (
      sql: (n: number) => string,
      value: unknown
    ) => {
      params.push(value);
      clauses.push(sql(params.length));
    };

    if (filters.query?.trim()) {
      const q = `%${filters.query.trim()}%`;
      params.push(q);
      const p = params.length;
      clauses.push(
        `(d.title ILIKE $${p} OR d.description ILIKE $${p} OR d.original_filename ILIKE $${p})`
      );
    }

    if (filters.category) {
      addFilter(
        n => `d.category = $${n}`,
        filters.category.trim()
      );
    }

    if (filters.ownerId) {
      addFilter(n => `d.owner_id = $${n}`, filters.ownerId);
    }

    if (filters.fromDate) {
      addFilter(n => `d.created_at >= $${n}`, filters.fromDate);
    }

    if (filters.toDate) {
      addFilter(n => `d.created_at <= $${n}`, filters.toDate);
    }

    const where = clauses.join(' AND ');

    const count = await postgresQuery<{ total: string }>(
      `SELECT COUNT(DISTINCT d.id)::text AS total
       FROM documents d
       LEFT JOIN document_permissions dp
         ON dp.document_id = d.id AND dp.user_id = $1
       WHERE ${where}`,
      params
    );

    const limit = Math.min(
      Math.max(Number(filters.limit) || 50, 1),
      200
    );
    const offset = Math.max(Number(filters.offset) || 0, 0);
    const pageParams = [...params, limit, offset];

    const result = await postgresQuery<DocumentRecord>(
      `SELECT d.*, u.name AS owner_name, u.email AS owner_email,
        CASE
          WHEN d.owner_id = $1 THEN 'owner'
          WHEN dp.permission_level = 'edit' THEN 'editor'
          WHEN dp.permission_level = 'view' THEN 'viewer'
          ELSE 'none'
        END AS user_permission
       FROM documents d
       JOIN users u ON u.id = d.owner_id
       LEFT JOIN document_permissions dp
         ON dp.document_id = d.id AND dp.user_id = $1
       WHERE ${where}
       ORDER BY d.updated_at DESC
       LIMIT $${pageParams.length - 1} OFFSET $${pageParams.length}`,
      pageParams
    );

    return {
      documents: result.rows.map(d => ({
        ...d,
        file_size_bytes: Number(d.file_size_bytes),
        version: Number(d.version)
      })),
      total: Number(count.rows[0]?.total || 0)
    };
  }

  public static async updateDocument(
    documentId: string,
    updater: Requester,
    updates: {
      title?: string;
      description?: string;
      category?: string;
      classification?: string;
      newFile?: {
        originalname: string;
        buffer: Buffer;
        size: number;
      };
    },
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<DocumentRecord> {
    const access = await PgPermissionService.checkAccess(
      documentId,
      updater.id,
      'edit'
    );

    if (!access.allowed) {
      await PgAuditService.recordEvent({
        actorId: updater.id,
        actorEmail: updater.email,
        actorRole: updater.role,
        action: 'ACCESS_DENIED_EDIT',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: access.documentTitle || 'Unknown Document',
        status: 'DENIED',
        details: { reason: access.reason },
        ipAddress,
        userAgent
      });

      throw httpError(
        access.reason || 'Edit permission required',
        403
      );
    }

    const result = await postgresQuery<DocumentRecord>(
      'SELECT * FROM documents WHERE id = $1',
      [documentId]
    );

    const existing = result.rows[0];

    if (!existing) {
      throw httpError('Document not found', 404);
    }

    let storagePath = existing.storage_path;
    let filename = existing.original_filename;
    let size = Number(existing.file_size_bytes);
    let mime = existing.mime_type;
    let checksum = existing.checksum_sha256;
    let version = Number(existing.version);
    let newStoragePath: string | undefined;

    if (updates.newFile) {
      const validation = FileService.validateUpload(
        updates.newFile
      );

      if (
        !validation.valid ||
        !validation.sanitizedFilename ||
        !validation.verifiedMime
      ) {
        throw httpError(
          `File validation failed: ${validation.error}`,
          400
        );
      }

      const stored = await SupabaseFileService.saveToVault(
        updates.newFile.buffer,
        validation.sanitizedFilename,
        validation.verifiedMime
      );

      newStoragePath = stored.storagePath;
      storagePath = stored.storagePath;
      filename = stored.originalFilename;
      size = stored.fileSizeBytes;
      mime = stored.mimeType;
      checksum = stored.checksumSha256;
      version += 1;
    }

    const title =
      updates.title !== undefined
        ? updates.title.trim()
        : existing.title;

    const description =
      updates.description !== undefined
        ? updates.description.trim() || null
        : existing.description;

    const category =
      updates.category !== undefined
        ? updates.category.trim()
        : existing.category;

    const classification =
      updates.classification !== undefined
        ? updates.classification.trim()
        : existing.classification;

    const now = new Date().toISOString();

    try {
      await postgresQuery(
        `UPDATE documents SET
          title=$1, description=$2, category=$3, classification=$4,
          storage_path=$5, original_filename=$6, file_size_bytes=$7,
          mime_type=$8, checksum_sha256=$9, version=$10, updated_at=$11
         WHERE id=$12`,
        [
          title,
          description,
          category,
          classification,
          storagePath,
          filename,
          size,
          mime,
          checksum,
          version,
          now,
          documentId
        ]
      );
    } catch (error) {
      if (newStoragePath) {
        try {
          await SupabaseFileService.deleteFromVault(
            newStoragePath
          );
        } catch (cleanupError) {
          console.error(
            'Failed to clean up replacement file after database update failure:',
            cleanupError
          );
        }
      }

      throw error;
    }

    // Database update succeeded; remove the previous object if replaced.
    if (newStoragePath) {
      try {
        await SupabaseFileService.deleteFromVault(
          existing.storage_path
        );
      } catch (cleanupError) {
        console.error(
          'Failed to delete previous Supabase file after replacement:',
          cleanupError
        );
      }
    }

    await PgAuditService.recordEvent({
      actorId: updater.id,
      actorEmail: updater.email,
      actorRole: updater.role,
      action: 'DOCUMENT_UPDATE',
      targetType: 'DOCUMENT',
      targetId: documentId,
      targetName: title,
      status: 'SUCCESS',
      details: {
        newVersion: version,
        fileReplaced: !!updates.newFile,
        titleChanged: title !== existing.title
      },
      ipAddress,
      userAgent
    });

    return {
      ...existing,
      title,
      description,
      category,
      classification,
      storage_path: storagePath,
      original_filename: filename,
      file_size_bytes: size,
      mime_type: mime,
      checksum_sha256: checksum,
      version,
      updated_at: now,
      user_permission: access.role
    };
  }

  public static async deleteDocument(
    documentId: string,
    requester: Requester,
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<void> {
    const access = await PgPermissionService.checkAccess(
      documentId,
      requester.id,
      'owner'
    );

    if (!access.allowed) {
      await PgAuditService.recordEvent({
        actorId: requester.id,
        actorEmail: requester.email,
        actorRole: requester.role,
        action: 'ACCESS_DENIED_DELETE',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: access.documentTitle || 'Unknown Document',
        status: 'DENIED',
        details: { reason: access.reason },
        ipAddress,
        userAgent
      });

      throw httpError(
        access.reason || 'Only the owner can delete this document',
        403
      );
    }

    const result = await postgresQuery<DocumentRecord>(
      'SELECT * FROM documents WHERE id = $1',
      [documentId]
    );

    const doc = result.rows[0];

    if (!doc) {
      throw httpError('Document not found', 404);
    }

    await postgresQuery(
      'DELETE FROM documents WHERE id = $1',
      [documentId]
    );

    try {
      await SupabaseFileService.deleteFromVault(
        doc.storage_path
      );
    } catch (storageError) {
      console.error(
        'Document record was deleted, but Supabase file cleanup failed:',
        storageError
      );
    }

    await PgAuditService.recordEvent({
      actorId: requester.id,
      actorEmail: requester.email,
      actorRole: requester.role,
      action: 'DOCUMENT_DELETE',
      targetType: 'DOCUMENT',
      targetId: documentId,
      targetName: doc.title,
      status: 'SUCCESS',
      details: {
        deletedFilename: doc.original_filename,
        deletedVersion: doc.version
      },
      ipAddress,
      userAgent
    });
  }
}
