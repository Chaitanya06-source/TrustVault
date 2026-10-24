import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { postgresPool } from '../db/postgres';
import { CONFIG } from '../config';

export interface PgAuditEventInput {
  actorId: string;
  actorEmail: string;
  actorRole: string;
  action: string;
  targetType: string;
  targetId?: string | null;
  targetName?: string | null;
  status: 'SUCCESS' | 'DENIED' | 'TAMPER_ALERT' | 'ERROR';
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

export interface PgAuditRecord {
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
  ip_address: string | null;
  user_agent: string | null;
  prev_hash: string | null;
  record_hash: string;
}

export interface PgVerificationResult {
  valid: boolean;
  totalRecords: number;
  brokenAt?: number;
  message: string;
  latestHash?: string;
  verifiedAt?: string;
}

export class PgAuditService {
  private static computeHash(
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
    ipAddress: string | null,
    prevHash: string | null,
    secret: string = CONFIG.AUDIT_HMAC_SECRET,
  ): string {
    const data = [
      sequenceNumber, timestamp, actorId, actorEmail, actorRole,
      action, targetType, targetId ?? '', status, detailsJson ?? '',
      ipAddress ?? '', prevHash ?? '',
    ].join('|');

    return crypto
      .createHmac('sha256', secret)
      .update(data)
      .digest('hex');
  }

  public static async recordEvent(
    input: PgAuditEventInput,
  ): Promise<PgAuditRecord> {
    const client = await postgresPool.connect();

    try {
      await client.query('BEGIN');
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtext('trustvault_audit_chain'))",
      );

      const latest = await client.query<{
        sequence_number: string;
        record_hash: string;
      }>(
        'SELECT sequence_number, record_hash FROM audit_logs ORDER BY sequence_number DESC LIMIT 1',
      );

      const sequenceNumber = latest.rows.length
        ? Number(latest.rows[0].sequence_number) + 1
        : 1;

      const prevHash = latest.rows[0]?.record_hash ?? '';
      const timestamp = new Date().toISOString();
      const detailsJson = input.details
        ? JSON.stringify(input.details)
        : null;
      const targetId = input.targetId ?? null;
      const targetName = input.targetName ?? null;
      const ipAddress = input.ipAddress ?? '127.0.0.1';
      const userAgent = input.userAgent ?? 'system';

      const recordHash = this.computeHash(
        sequenceNumber, timestamp, input.actorId, input.actorEmail,
        input.actorRole, input.action, input.targetType, targetId,
        input.status, detailsJson, ipAddress, prevHash,
      );

      const result = await client.query<PgAuditRecord>(
        `INSERT INTO audit_logs (
          id, sequence_number, timestamp, actor_id, actor_email,
          actor_role, action, target_type, target_id, target_name,
          status, details_json, ip_address, user_agent, prev_hash, record_hash
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
        ) RETURNING *`,
        [
          uuidv4(), sequenceNumber, timestamp, input.actorId,
          input.actorEmail, input.actorRole, input.action,
          input.targetType, targetId, targetName, input.status,
          detailsJson, ipAddress, userAgent, prevHash, recordHash,
        ],
      );

      await client.query('COMMIT');
      return result.rows[0];
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  public static async verifyChainIntegrity(): Promise<PgVerificationResult> {
    const result = await postgresPool.query<PgAuditRecord>(
      'SELECT * FROM audit_logs ORDER BY sequence_number ASC',
    );

    let expectedPrevHash = '';
    let expectedSequence = 1;

    for (const row of result.rows) {
      const sequenceNumber = Number(row.sequence_number);

      if (
        sequenceNumber !== expectedSequence ||
        row.prev_hash !== expectedPrevHash
      ) {
        return {
          valid: false,
          totalRecords: result.rows.length,
          brokenAt: sequenceNumber,
          message: 'Audit chain sequence or previous hash mismatch',
        };
      }

      // The active key signs new records. Optional legacy keys are verification-only.
      // Set AUDIT_HMAC_LEGACY_SECRETS to a comma-separated list of old keys in the host environment.
      const verificationSecrets = [
        CONFIG.AUDIT_HMAC_SECRET,
        ...(process.env.AUDIT_HMAC_LEGACY_SECRETS ?? '')
          .split(',')
          .map((secret) => secret.trim())
          .filter(Boolean),
      ];
      const hashMatches = [...new Set(verificationSecrets)].some((secret) => {
        const calculatedHash = this.computeHash(
          sequenceNumber, row.timestamp, row.actor_id, row.actor_email,
          row.actor_role, row.action, row.target_type, row.target_id,
          row.status, row.details_json, row.ip_address, row.prev_hash, secret,
        );
        return calculatedHash === row.record_hash;
      });

      if (!hashMatches) {
        return {
          valid: false,
          totalRecords: result.rows.length,
          brokenAt: sequenceNumber,
          message: 'Audit record hash mismatch',
        };
      }

      expectedPrevHash = row.record_hash;
      expectedSequence++;
    }

    return {
      valid: true,
      totalRecords: result.rows.length,
      message: 'Audit chain integrity verified',
      latestHash: result.rows.length > 0
        ? result.rows[result.rows.length - 1].record_hash
        : '',
      verifiedAt: new Date().toISOString(),
    };
  }

  public static async getLogs(filters: {
    actorId?: string;
    documentId?: string;
    action?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ logs: PgAuditRecord[]; total: number }> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filters.actorId) {
      params.push(filters.actorId);
      conditions.push(`actor_id = $${params.length}`);
    }
    if (filters.documentId) {
      params.push(filters.documentId);
      conditions.push(`target_id = $${params.length}`);
    }
    if (filters.action) {
      params.push(filters.action);
      conditions.push(`action = $${params.length}`);
    }
    if (filters.status) {
      params.push(filters.status);
      conditions.push(`status = $${params.length}`);
    }

    const whereSql = conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const countResult = await postgresPool.query<{ count: string }>(
      `SELECT COUNT(*) AS count FROM audit_logs ${whereSql}`,
      params,
    );

    const total = Number(countResult.rows[0]?.count ?? 0);
    const limit = Math.min(Math.max(filters.limit ?? 50, 1), 200);
    const offset = Math.max(filters.offset ?? 0, 0);
    const logParams = [...params, limit, offset];

    const logsResult = await postgresPool.query<PgAuditRecord>(
      `SELECT * FROM audit_logs ${whereSql}
       ORDER BY sequence_number DESC
       LIMIT $${logParams.length - 1}
       OFFSET $${logParams.length}`,
      logParams,
    );

    return { logs: logsResult.rows, total };
  }

  public static async getSecurityAlerts(): Promise<Array<{
    type: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    title: string;
    description: string;
    count: number;
    lastDetected: string;
    targetId?: string;
    actorEmail?: string;
  }>> {
    const alerts: Array<{
      type: string;
      severity: 'HIGH' | 'MEDIUM' | 'LOW';
      title: string;
      description: string;
      count: number;
      lastDetected: string;
      targetId?: string;
      actorEmail?: string;
    }> = [];

    const deniedResult = await postgresPool.query<{
      actor_email: string;
      denied_count: string;
      last_seen: string;
    }>(`
      SELECT actor_email, COUNT(*) AS denied_count,
             MAX(timestamp) AS last_seen
      FROM audit_logs
      WHERE status = 'DENIED'
      GROUP BY actor_email
      HAVING COUNT(*) >= 2
      ORDER BY COUNT(*) DESC
    `);

    for (const item of deniedResult.rows) {
      const count = Number(item.denied_count);
      alerts.push({
        type: 'DENIED_ACCESS_SPIKE',
        severity: count >= 5 ? 'HIGH' : 'MEDIUM',
        title: 'Repeated Unauthorized Probing',
        description: `User '${item.actor_email}' has generated ${count} unauthorized access rejections.`,
        count,
        lastDetected: item.last_seen,
        actorEmail: item.actor_email,
      });
    }

    const attackedDocs = await postgresPool.query<{
      target_id: string;
      target_name: string | null;
      hit_count: string;
      last_seen: string;
    }>(`
      SELECT target_id, MAX(target_name) AS target_name,
             COUNT(*) AS hit_count, MAX(timestamp) AS last_seen
      FROM audit_logs
      WHERE status = 'DENIED'
        AND target_type = 'DOCUMENT'
        AND target_id IS NOT NULL
      GROUP BY target_id
      HAVING COUNT(*) >= 2
      ORDER BY COUNT(*) DESC
    `);

    for (const item of attackedDocs.rows) {
      const count = Number(item.hit_count);
      alerts.push({
        type: 'TARGETED_DOCUMENT_PROBING',
        severity: 'HIGH',
        title: 'Document Target of Unauthorized Requests',
        description: `Document '${item.target_name || item.target_id}' received ${count} refused access requests.`,
        count,
        lastDetected: item.last_seen,
        targetId: item.target_id,
      });
    }

    return alerts;
  }
}