import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../db/database';
import { CONFIG } from '../config';

export interface AuditEventInput {
  actorId: string;
  actorEmail: string;
  actorRole: string;
  action: string;
  targetType: 'DOCUMENT' | 'USER' | 'PERMISSION' | 'AUTH' | 'SYSTEM' | 'AI_ADVISORY';
  targetId?: string | null;
  targetName?: string | null;
  status: 'SUCCESS' | 'DENIED' | 'TAMPER_ALERT' | 'ERROR';
  details?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
}

export interface AuditRecord {
  id: string;
  sequence_number: number;
  timestamp: string;
  actor_id: string;
  actor_email: string;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string | null;
  target_name: string | null;
  status: 'SUCCESS' | 'DENIED' | 'TAMPER_ALERT' | 'ERROR';
  details_json: string | null;
  ip_address: string;
  user_agent: string;
  prev_hash: string;
  record_hash: string;
}

export interface VerificationResult {
  valid: boolean;
  totalRecords: number;
  genesisHash?: string;
  latestHash?: string;
  brokenAtIndex?: number;
  brokenRecordId?: string;
  failureReason?: string;
  verifiedAt: string;
}

const GENESIS_PREV_HASH = '0'.repeat(64);

export class AuditService {
  /**
   * Computes the HMAC-SHA256 signature for an audit log entry.
   * Every critical field is bound into the cryptographic hash.
   */
  public static computeHash(
    sequenceNumber: number,
    timestamp: string,
    actorId: string,
    actorEmail: string,
    actorRole: string,
    action: string,
    targetType: string,
    targetId: string | null,
    status: string,
    detailsJson: string | null,
    ipAddress: string,
    prevHash: string
  ): string {
    const rawPayload = [
      sequenceNumber,
      timestamp,
      actorId,
      actorEmail,
      actorRole,
      action,
      targetType,
      targetId || '',
      status,
      detailsJson || '',
      ipAddress,
      prevHash
    ].join('|');

    return crypto
      .createHmac('sha256', CONFIG.AUDIT_HMAC_SECRET)
      .update(rawPayload)
      .digest('hex');
  }

  /**
   * Atomically records an event into the tamper-evident hash-chained audit ledger.
   */
  public static recordEvent(event: AuditEventInput): AuditRecord {
    const db = getDatabase();

    // Query the latest record to get the chain link
    const lastRecord = db
      .prepare('SELECT sequence_number, record_hash FROM audit_logs ORDER BY sequence_number DESC LIMIT 1')
      .get() as { sequence_number: number; record_hash: string } | undefined;

    const sequenceNumber = lastRecord ? lastRecord.sequence_number + 1 : 0;
    const prevHash = lastRecord ? lastRecord.record_hash : GENESIS_PREV_HASH;
    const id = uuidv4();
    const timestamp = new Date().toISOString();
    const ipAddress = event.ipAddress || '127.0.0.1';
    const userAgent = event.userAgent || 'system';
    const detailsJson = event.details ? JSON.stringify(event.details) : null;
    const targetId = event.targetId || null;
    const targetName = event.targetName || null;

    const recordHash = this.computeHash(
      sequenceNumber,
      timestamp,
      event.actorId,
      event.actorEmail,
      event.actorRole,
      event.action,
      event.targetType,
      targetId,
      event.status,
      detailsJson,
      ipAddress,
      prevHash
    );

    const stmt = db.prepare(`
      INSERT INTO audit_logs (
        id, sequence_number, timestamp, actor_id, actor_email, actor_role,
        action, target_type, target_id, target_name, status, details_json,
        ip_address, user_agent, prev_hash, record_hash
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?
      )
    `);

    stmt.run(
      id,
      sequenceNumber,
      timestamp,
      event.actorId,
      event.actorEmail,
      event.actorRole,
      event.action,
      event.targetType,
      targetId,
      targetName,
      event.status,
      detailsJson,
      ipAddress,
      userAgent,
      prevHash,
      recordHash
    );

    return {
      id,
      sequence_number: sequenceNumber,
      timestamp,
      actor_id: event.actorId,
      actor_email: event.actorEmail,
      actor_role: event.actorRole,
      action: event.action,
      target_type: event.targetType,
      target_id: targetId,
      target_name: targetName,
      status: event.status,
      details_json: detailsJson,
      ip_address: ipAddress,
      user_agent: userAgent,
      prev_hash: prevHash,
      record_hash: recordHash
    };
  }

  /**
   * Verifies the cryptographic integrity of the entire audit hash chain.
   * Any insertion, deletion, reordering, or field modification will be detected.
   */
  public static verifyChainIntegrity(): VerificationResult {
    const db = getDatabase();
    const records = db
      .prepare('SELECT * FROM audit_logs ORDER BY sequence_number ASC')
      .all() as unknown as AuditRecord[];

    const verifiedAt = new Date().toISOString();

    if (records.length === 0) {
      return {
        valid: true,
        totalRecords: 0,
        verifiedAt
      };
    }

    let expectedPrevHash = GENESIS_PREV_HASH;

    for (let i = 0; i < records.length; i++) {
      const record = records[i];

      // Check 1: Sequence number continuity
      if (record.sequence_number !== i) {
        return {
          valid: false,
          totalRecords: records.length,
          brokenAtIndex: i,
          brokenRecordId: record.id,
          failureReason: `Sequence break: expected index ${i}, but found ${record.sequence_number}`,
          verifiedAt
        };
      }

      // Check 2: Previous hash link
      if (record.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          totalRecords: records.length,
          brokenAtIndex: i,
          brokenRecordId: record.id,
          failureReason: `Broken chain link at index ${i}: prev_hash does not match preceding record_hash`,
          verifiedAt
        };
      }

      // Check 3: Cryptographic hash recalculation
      const recalculatedHash = this.computeHash(
        record.sequence_number,
        record.timestamp,
        record.actor_id,
        record.actor_email,
        record.actor_role,
        record.action,
        record.target_type,
        record.target_id,
        record.status,
        record.details_json,
        record.ip_address,
        record.prev_hash
      );

      if (recalculatedHash !== record.record_hash) {
        return {
          valid: false,
          totalRecords: records.length,
          brokenAtIndex: i,
          brokenRecordId: record.id,
          failureReason: `Tampered record detected at index ${i}: signature mismatch. Data altered!`,
          verifiedAt
        };
      }

      expectedPrevHash = record.record_hash;
    }

    return {
      valid: true,
      totalRecords: records.length,
      genesisHash: records[0].record_hash,
      latestHash: records[records.length - 1].record_hash,
      verifiedAt
    };
  }

  /**
   * Retrieves audit logs with optional filtering.
   */
  public static getLogs(filters: {
    actorId?: string;
    documentId?: string;
    action?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): { logs: AuditRecord[]; total: number } {
    const db = getDatabase();
    const whereClauses: string[] = [];
    const params: any[] = [];

    if (filters.actorId) {
      whereClauses.push('actor_id = ?');
      params.push(filters.actorId);
    }
    if (filters.documentId) {
      whereClauses.push('target_id = ?');
      params.push(filters.documentId);
    }
    if (filters.action) {
      whereClauses.push('action = ?');
      params.push(filters.action);
    }
    if (filters.status) {
      whereClauses.push('status = ?');
      params.push(filters.status);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const countRow = db.prepare(`SELECT COUNT(*) as count FROM audit_logs ${whereSql}`).get(...params) as { count: number };
    const total = countRow ? countRow.count : 0;

    const limit = filters.limit || 50;
    const offset = filters.offset || 0;

    const logs = db
      .prepare(`SELECT * FROM audit_logs ${whereSql} ORDER BY sequence_number DESC LIMIT ? OFFSET ?`)
     .all(...params, limit, offset) as unknown as AuditRecord[];

    return { logs, total };
  }

  /**
   * Computes security anomalies and alerts (e.g. repeated denied downloads, unauthorized attempts).
   */
  public static getSecurityAlerts(): Array<{
    type: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    title: string;
    description: string;
    count: number;
    lastDetected: string;
    targetId?: string;
    actorEmail?: string;
  }> {
    const db = getDatabase();
    const alerts: Array<any> = [];

    // Alert 1: Spikes in DENIED access attempts by actor
    const deniedActors = db.prepare(`
      SELECT actor_email, COUNT(*) as denied_count, MAX(timestamp) as last_seen
      FROM audit_logs
      WHERE status = 'DENIED'
      GROUP BY actor_email
      HAVING denied_count >= 2
      ORDER BY denied_count DESC
    `).all() as Array<{ actor_email: string; denied_count: number; last_seen: string }>;

    for (const item of deniedActors) {
      alerts.push({
        type: 'DENIED_ACCESS_SPIKE',
        severity: item.denied_count >= 5 ? 'HIGH' : 'MEDIUM',
        title: `Repeated Unauthorized Probing`,
        description: `User '${item.actor_email}' has generated ${item.denied_count} unauthorized access rejections.`,
        count: item.denied_count,
        lastDetected: item.last_seen,
        actorEmail: item.actor_email
      });
    }

    // Alert 2: Repeated unauthorized attempts on specific confidential documents
    const attackedDocs = db.prepare(`
      SELECT target_id, target_name, COUNT(*) as hit_count, MAX(timestamp) as last_seen
      FROM audit_logs
      WHERE status = 'DENIED' AND target_type = 'DOCUMENT' AND target_id IS NOT NULL
      GROUP BY target_id
      HAVING hit_count >= 2
      ORDER BY hit_count DESC
    `).all() as Array<{ target_id: string; target_name: string; hit_count: number; last_seen: string }>;

    for (const item of attackedDocs) {
      alerts.push({
        type: 'TARGETED_DOCUMENT_PROBING',
        severity: 'HIGH',
        title: `Document Target of Unauthorized Requests`,
        description: `Document '${item.target_name || item.target_id}' received ${item.hit_count} refused access requests.`,
        count: item.hit_count,
        lastDetected: item.last_seen,
        targetId: item.target_id
      });
    }

    return alerts;
  }
}
