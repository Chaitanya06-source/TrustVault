import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/app';
import { getDatabase } from '../src/db/database';
import { runSeed } from '../src/db/seed';
import { AuditService } from '../src/services/auditService';

describe('Tamper-Evident Audit Ledger & Cryptographic Chain Tests', () => {
  let adminToken: string;
  let eveToken: string;

  beforeAll(async () => {
    getDatabase();
    runSeed();

    const adminRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'admin@trustvault.internal', password: 'AdminPassword123!' });
    adminToken = adminRes.body.token;

    const eveRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'eve@external.org', password: 'EvePassword123!' });
    eveToken = eveRes.body.token;
  });

  it('Verifies that unauthorized access attempts are recorded as DENIED in the audit trail', async () => {
    // Eve triggers an unauthorized probe
    await request(app)
      .get('/api/documents/non-existent-or-forbidden-id/download')
      .set('Authorization', `Bearer ${eveToken}`);

    // Fetch audit records as admin
    const auditRes = await request(app)
      .get('/api/audit?status=DENIED')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(auditRes.status).toBe(200);
    expect(auditRes.body.logs.length).toBeGreaterThan(0);

    const deniedLog = auditRes.body.logs.find((l: any) => l.actor_email === 'eve@external.org');
    expect(deniedLog).toBeDefined();
    expect(deniedLog.status).toBe('DENIED');
  });

  it('Verifies the cryptographic audit hash chain is valid under normal operation', () => {
    const result = AuditService.verifyChainIntegrity();
    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBeGreaterThan(0);
    expect(result.genesisHash).toBeDefined();
    expect(result.latestHash).toBeDefined();
  });

  it('Proves that QUIET ALTERATION of an audit record is immediately detected as TAMPERING', () => {
    const db = getDatabase();

    // Pick record at sequence 3
    const targetRecord = db
      .prepare('SELECT id, actor_email, sequence_number FROM audit_logs WHERE sequence_number = 3')
      .get() as any;

    expect(targetRecord).toBeDefined();
    const originalEmail = targetRecord.actor_email;

    try {
      // Simulate an internal attacker modifying the database directly to frame another user
      db.prepare(`UPDATE audit_logs SET actor_email = 'framed_victim@external.org' WHERE sequence_number = 3`).run();

      // Now run cryptographic chain verification
      const verifyResult = AuditService.verifyChainIntegrity();

      // Verification MUST FAIL
      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.brokenAtIndex).toBe(3);
      expect(verifyResult.brokenRecordId).toBe(targetRecord.id);
      expect(verifyResult.failureReason).toContain('Tampered record detected at index 3');
    } finally {
      // Revert change to restore chain for subsequent tests
      db.prepare(`UPDATE audit_logs SET actor_email = ? WHERE sequence_number = 3`).run(originalEmail);
    }

    // After restoring the exact original data, chain is verified again
    const restoredVerify = AuditService.verifyChainIntegrity();
    expect(restoredVerify.valid).toBe(true);
  });

  it('Proves that DELETING an audit record breaks sequence continuity', () => {
    const db = getDatabase();

    // Fetch highest sequence number
    const highest = db.prepare('SELECT sequence_number, id FROM audit_logs ORDER BY sequence_number DESC LIMIT 1').get() as any;
    const tempSeq = highest.sequence_number + 1;

    // Insert a dummy record at tempSeq
    db.prepare(`
      INSERT INTO audit_logs (
        id, sequence_number, timestamp, actor_id, actor_email, actor_role,
        action, target_type, status, ip_address, user_agent, prev_hash, record_hash
      ) VALUES (
        'dummy-id', ?, '2026-10-20T12:00:00.000Z', 'dummy', 'dummy@test.com', 'admin',
        'TEST_ACTION', 'SYSTEM', 'SUCCESS', '127.0.0.1', 'test', 'fake', 'fake'
      )
    `).run(tempSeq + 1); // Notice gap: inserted at tempSeq + 1, skipping tempSeq

    const result = AuditService.verifyChainIntegrity();
    expect(result.valid).toBe(false);
    expect(result.failureReason).toContain('Sequence break');

    // Clean up
    db.prepare(`DELETE FROM audit_logs WHERE id = 'dummy-id'`).run();
  });
});
