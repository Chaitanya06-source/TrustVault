import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../db/database';
import { FileService } from './fileService';
import { PermissionService, AccessRole } from './permissionService';
import { AuditService } from './auditService';

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

export class DocumentService {
  /**
   * Securely uploads a document to the vault with full validation and auditing.
   */
  public static uploadDocument(
    owner: { id: string; email: string; role: string },
    file: { originalname: string; buffer: Buffer; size: number },
    metadata: { title: string; description?: string; category: string; classification?: string },
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): DocumentRecord {
    // 1. Strict File Validation (size, extension, sanitization, magic bytes)
    const validation = FileService.validateUpload(file);
    if (!validation.valid || !validation.sanitizedFilename || !validation.verifiedMime) {
      AuditService.recordEvent({
        actorId: owner.id,
        actorEmail: owner.email,
        actorRole: owner.role,
        action: 'DOCUMENT_UPLOAD_REJECTED',
        targetType: 'DOCUMENT',
        status: 'DENIED',
        details: { filename: file.originalname, size: file.size, reason: validation.error },
        ipAddress,
        userAgent
      });
      throw new Error(`File validation failed: ${validation.error}`);
    }

    // 2. Store file in vault storage under non-predictable UUID
    const stored = FileService.saveToVault(file.buffer, validation.sanitizedFilename, validation.verifiedMime);

    const docId = uuidv4();
    const now = new Date().toISOString();
    const classification = metadata.classification || 'Confidential';

    // 3. Insert record into database
    const db = getDatabase();
    db.prepare(`
      INSERT INTO documents (
        id, title, description, category, classification, owner_id,
        storage_path, original_filename, file_size_bytes, mime_type,
        checksum_sha256, version, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?
      )
    `).run(
      docId,
      metadata.title.trim(),
      metadata.description ? metadata.description.trim() : null,
      metadata.category.trim(),
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
    );

    // 4. Audit upload in tamper-evident ledger
    AuditService.recordEvent({
      actorId: owner.id,
      actorEmail: owner.email,
      actorRole: owner.role,
      action: 'DOCUMENT_UPLOAD',
      targetType: 'DOCUMENT',
      targetId: docId,
      targetName: metadata.title.trim(),
      status: 'SUCCESS',
      details: {
        filename: stored.originalFilename,
        fileSize: stored.fileSizeBytes,
        mimeType: stored.mimeType,
        checksum: stored.checksumSha256,
        category: metadata.category,
        classification
      },
      ipAddress,
      userAgent
    });

    return {
      id: docId,
      title: metadata.title.trim(),
      description: metadata.description || null,
      category: metadata.category.trim(),
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

  /**
   * Retrieves document metadata if user has active permissions.
   * Enforces zero-trust and logs refused attempts.
   */
  public static getDocumentById(
    documentId: string,
    requester: { id: string; email: string; role: string },
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): DocumentRecord {
    // 1. Evaluate permissions in real-time
    const access = PermissionService.checkAccess(documentId, requester.id, 'view');

    if (!access.allowed) {
      AuditService.recordEvent({
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

      const err: any = new Error(access.reason || 'Access denied: You do not have permission to view this document');
      err.statusCode = access.role === 'none' ? 403 : 403;
      throw err;
    }

    // 2. Fetch document record
    const db = getDatabase();
    const doc = db.prepare(`
      SELECT d.*, u.name as owner_name, u.email as owner_email
      FROM documents d
      JOIN users u ON d.owner_id = u.id
      WHERE d.id = ?
    `).get(documentId) as (DocumentRecord & { owner_name: string; owner_email: string }) | undefined;

    if (!doc) {
      const err: any = new Error('Document not found');
      err.statusCode = 404;
      throw err;
    }

    doc.user_permission = access.role;
    return doc;
  }

  /**
   * Safely serves document file stream if and only if caller has active permission.
   * Enforces immediate revocation check right before streaming bytes.
   */
  public static getFileForDownload(
    documentId: string,
    requester: { id: string; email: string; role: string },
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): { filePath: string; filename: string; mimeType: string; fileSize: number; checksum: string } {
    // Real-time permission gate
    const access = PermissionService.checkAccess(documentId, requester.id, 'view');

    if (!access.allowed) {
      AuditService.recordEvent({
        actorId: requester.id,
        actorEmail: requester.email,
        actorRole: requester.role,
        action: 'ACCESS_DENIED_DOWNLOAD',
        targetType: 'DOCUMENT',
        targetId: documentId,
        targetName: access.documentTitle || 'Unknown Document',
        status: 'DENIED',
        details: { reason: access.reason, attemptedDownload: true },
        ipAddress,
        userAgent
      });

      const err: any = new Error('Access denied: You do not have permission to download this document');
      err.statusCode = 403;
      throw err;
    }

    const db = getDatabase();
    const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(documentId) as DocumentRecord | undefined;

    if (!doc) {
      const err: any = new Error('Document not found');
      err.statusCode = 404;
      throw err;
    }

    const filePath = FileService.getStorageFilePath(doc.storage_path);

    // Audit successful download
    AuditService.recordEvent({
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
      filePath,
      filename: doc.original_filename,
      mimeType: doc.mime_type,
      fileSize: doc.file_size_bytes,
      checksum: doc.checksum_sha256
    };
  }

  /**
   * Searches and filters documents accessible to the requester.
   * Users can only see documents they own or have been granted access to.
   */
  public static searchDocuments(
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
  ): { documents: DocumentRecord[]; total: number } {
    const db = getDatabase();

    const whereClauses: string[] = [];
    const params: any[] = [];

    // Zero-Trust Boundary: Must be owner OR have active grant in document_permissions
    whereClauses.push(`(d.owner_id = ? OR dp.user_id = ?)`);
    params.push(requester.id, requester.id);

    if (filters.query) {
      whereClauses.push(`(d.title LIKE ? OR d.description LIKE ? OR d.original_filename LIKE ?)`);
      const like = `%${filters.query.trim()}%`;
      params.push(like, like, like);
    }

    if (filters.category) {
      whereClauses.push(`d.category = ?`);
      params.push(filters.category.trim());
    }

    if (filters.ownerId) {
      whereClauses.push(`d.owner_id = ?`);
      params.push(filters.ownerId);
    }

    if (filters.fromDate) {
      whereClauses.push(`d.created_at >= ?`);
      params.push(filters.fromDate);
    }

    if (filters.toDate) {
      whereClauses.push(`d.created_at <= ?`);
      params.push(filters.toDate);
    }

    const whereSql = whereClauses.join(' AND ');

    const countRow = db.prepare(`
      SELECT COUNT(DISTINCT d.id) as total
      FROM documents d
      LEFT JOIN document_permissions dp ON d.id = dp.document_id AND dp.user_id = ?
      WHERE ${whereSql}
    `).get(requester.id, ...params) as { total: number };

    const total = countRow ? countRow.total : 0;
    const limit = filters.limit || 50;
    const offset = filters.offset || 0;

    const rows = db.prepare(`
      SELECT
        d.*,
        u.name as owner_name,
        u.email as owner_email,
        CASE
          WHEN d.owner_id = ? THEN 'owner'
          WHEN dp.permission_level = 'edit' THEN 'editor'
          WHEN dp.permission_level = 'view' THEN 'viewer'
          ELSE 'none'
        END as user_permission
      FROM documents d
      JOIN users u ON d.owner_id = u.id
      LEFT JOIN document_permissions dp ON d.id = dp.document_id AND dp.user_id = ?
      WHERE ${whereSql}
      GROUP BY d.id
      ORDER BY d.updated_at DESC
      LIMIT ? OFFSET ?
    `).all(requester.id, requester.id, ...params, limit, offset) as unknown as DocumentRecord[];
    return { documents: rows, total };
  }

  /**
   * Updates document metadata or uploads a new version.
   * Requires 'edit' or 'owner' permission.
   */
  public static updateDocument(
    documentId: string,
    updater: { id: string; email: string; role: string },
    updates: {
      title?: string;
      description?: string;
      category?: string;
      classification?: string;
      newFile?: { originalname: string; buffer: Buffer; size: number };
    },
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): DocumentRecord {
    // 1. Permission check: requires 'edit'
    const access = PermissionService.checkAccess(documentId, updater.id, 'edit');

    if (!access.allowed) {
      AuditService.recordEvent({
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

      const err: any = new Error(access.reason || 'Edit permission required');
      err.statusCode = 403;
      throw err;
    }

    const db = getDatabase();
    const existing = db.prepare('SELECT * FROM documents WHERE id = ?').get(documentId) as unknown as DocumentRecord;
    const now = new Date().toISOString();

    let storagePath = existing.storage_path;
    let originalFilename = existing.original_filename;
    let fileSizeBytes = existing.file_size_bytes;
    let mimeType = existing.mime_type;
    let checksumSha256 = existing.checksum_sha256;
    let version = existing.version;

    // If replacement file is provided, validate and store
    if (updates.newFile) {
      const validation = FileService.validateUpload(updates.newFile);
      if (!validation.valid || !validation.sanitizedFilename || !validation.verifiedMime) {
        throw new Error(`File validation failed: ${validation.error}`);
      }

      // Save new file to vault
      const stored = FileService.saveToVault(updates.newFile.buffer, validation.sanitizedFilename, validation.verifiedMime);

      // Clean up old physical file
      FileService.deleteFromVault(existing.storage_path);

      storagePath = stored.storagePath;
      originalFilename = stored.originalFilename;
      fileSizeBytes = stored.fileSizeBytes;
      mimeType = stored.mimeType;
      checksumSha256 = stored.checksumSha256;
      version += 1;
    }

    const title = updates.title !== undefined ? updates.title.trim() : existing.title;
    const description = updates.description !== undefined ? updates.description.trim() : existing.description;
    const category = updates.category !== undefined ? updates.category.trim() : existing.category;
    const classification = updates.classification !== undefined ? updates.classification.trim() : existing.classification;

    db.prepare(`
      UPDATE documents
      SET title = ?, description = ?, category = ?, classification = ?,
          storage_path = ?, original_filename = ?, file_size_bytes = ?,
          mime_type = ?, checksum_sha256 = ?, version = ?, updated_at = ?
      WHERE id = ?
    `).run(
      title,
      description,
      category,
      classification,
      storagePath,
      originalFilename,
      fileSizeBytes,
      mimeType,
      checksumSha256,
      version,
      now,
      documentId
    );

    // Audit update
    AuditService.recordEvent({
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
      original_filename: originalFilename,
      file_size_bytes: fileSizeBytes,
      mime_type: mimeType,
      checksum_sha256: checksumSha256,
      version,
      updated_at: now,
      user_permission: access.role
    };
  }

  /**
   * Deletes a document. Only the document owner can delete.
   */
  public static deleteDocument(
    documentId: string,
    requester: { id: string; email: string; role: string },
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): void {
    // 1. Permission check: requires 'owner'
    const access = PermissionService.checkAccess(documentId, requester.id, 'owner');

    if (!access.allowed) {
      AuditService.recordEvent({
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

      const err: any = new Error(access.reason || 'Only the document owner can delete this document');
      err.statusCode = 403;
      throw err;
    }

    const db = getDatabase();
    const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(documentId) as DocumentRecord | undefined;

    if (!doc) {
      const err: any = new Error('Document not found');
      err.statusCode = 404;
      throw err;
    }

    // 2. Remove physical file from disk
    FileService.deleteFromVault(doc.storage_path);

    // 3. Delete database record (cascades permissions)
    db.prepare('DELETE FROM documents WHERE id = ?').run(documentId);

    // 4. Audit deletion
    AuditService.recordEvent({
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
