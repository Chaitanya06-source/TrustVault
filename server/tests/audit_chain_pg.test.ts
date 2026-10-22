import { afterEach, describe, expect, it, vi } from 'vitest';

const { queryMock } = vi.hoisted(() => ({
  queryMock: vi.fn()
}));

vi.mock('../src/db/postgres', () => ({
  postgresPool: {
    query: queryMock,
    connect: vi.fn()
  }
}));

import { PgAuditService } from '../src/services/auditService.pg';

describe('PostgreSQL audit-chain integrity', () => {
  afterEach(() => queryMock.mockReset());

  it('accepts an empty audit chain', async () => {
    queryMock.mockResolvedValueOnce({ rows: [] });

    const result = await PgAuditService.verifyChainIntegrity();

    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(0);
  });

  it('detects a broken sequence or previous hash', async () => {
    queryMock.mockResolvedValueOnce({
      rows: [{
        sequence_number: '2',
        prev_hash: 'unexpected',
        record_hash: 'fake',
        timestamp: new Date().toISOString(),
        actor_id: 'user-1',
        actor_email: 'user@example.test',
        actor_role: 'user',
        action: 'DOCUMENT_DOWNLOAD',
        target_type: 'DOCUMENT',
        target_id: 'doc-1',
        status: 'SUCCESS',
        details_json: '{}',
        ip_address: '127.0.0.1'
      }]
    });

    const result = await PgAuditService.verifyChainIntegrity();

    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
    expect(result.message).toContain('sequence or previous hash mismatch');
  });

  it('detects a record whose hash does not match its contents', async () => {
    queryMock.mockResolvedValueOnce({
      rows: [{
        sequence_number: '1',
        prev_hash: '',
        record_hash: 'tampered-hash',
        timestamp: new Date().toISOString(),
        actor_id: 'user-1',
        actor_email: 'user@example.test',
        actor_role: 'user',
        action: 'DOCUMENT_DOWNLOAD',
        target_type: 'DOCUMENT',
        target_id: 'doc-1',
        status: 'SUCCESS',
        details_json: '{}',
        ip_address: '127.0.0.1'
      }]
    });

    const result = await PgAuditService.verifyChainIntegrity();

    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.message).toBe('Audit record hash mismatch');
  });
});
