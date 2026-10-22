import { afterEach, describe, expect, it, vi } from 'vitest';

const { postgresQueryMock, auditMock, permissionMock } = vi.hoisted(() => ({
  postgresQueryMock: vi.fn(),
  auditMock: vi.fn(),
  permissionMock: {
    checkAccess: vi.fn(),
    grantPermission: vi.fn(),
    revokePermission: vi.fn()
  }
}));

vi.mock('../src/db/postgres', () => ({
  postgresQuery: postgresQueryMock
}));

vi.mock('../src/services/auditService.pg', () => ({
  PgAuditService: { recordEvent: auditMock }
}));

vi.mock('../src/services/permissionService.pg', () => ({
  PgPermissionService: permissionMock
}));

import { AiAdvisoryService } from '../src/services/aiAdvisoryService.pg';

const owner = {
  id: 'owner-1',
  email: 'owner@example.test',
  role: 'owner'
};

const pendingAdvisory = {
  id: 'advisory-1',
  document_id: 'doc-1',
  document_title: 'Payroll records',
  actor_id: 'owner-1',
  status: 'PENDING'
};

describe('AI advisory human decisions', () => {
  afterEach(() => {
    postgresQueryMock.mockReset();
    auditMock.mockReset();
    permissionMock.checkAccess.mockReset();
    permissionMock.grantPermission.mockReset();
    permissionMock.revokePermission.mockReset();
  });

  it('applies only human-confirmed grants and audits acceptance', async () => {
    postgresQueryMock
      .mockResolvedValueOnce({ rows: [pendingAdvisory] })
      .mockResolvedValueOnce({ rows: [] });

    permissionMock.grantPermission.mockResolvedValueOnce({});
    auditMock.mockResolvedValueOnce(undefined);

    const result = await AiAdvisoryService.confirmDecision(
      owner,
      'doc-1',
      'advisory-1',
      'ACCEPTED',
      [{ userId: 'viewer-1', permissionLevel: 'view' }]
    );

    expect(permissionMock.grantPermission).toHaveBeenCalledTimes(1);
    expect(permissionMock.grantPermission).toHaveBeenCalledWith(
      'doc-1',
      'owner-1',
      'owner@example.test',
      'owner',
      'viewer-1',
      'view',
      '127.0.0.1',
      'client'
    );
    expect(result.appliedGrantsCount).toBe(1);
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'AI_ADVISORY_CONFIRMED',
        status: 'SUCCESS',
        details: expect.objectContaining({
          decision: 'ACCEPTED',
          appliedGrantsCount: 1
        })
      })
    );
  });

  it('does not grant access when a human rejects the recommendation', async () => {
    postgresQueryMock
      .mockResolvedValueOnce({ rows: [pendingAdvisory] })
      .mockResolvedValueOnce({ rows: [] });

    auditMock.mockResolvedValueOnce(undefined);

    const result = await AiAdvisoryService.confirmDecision(
      owner,
      'doc-1',
      'advisory-1',
      'REJECTED',
      [{ userId: 'viewer-1', permissionLevel: 'view' }]
    );

    expect(result.appliedGrantsCount).toBe(0);
    expect(permissionMock.grantPermission).not.toHaveBeenCalled();
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'AI_ADVISORY_REJECTED',
        status: 'SUCCESS'
      })
    );
  });

  it('rejects a decision from someone other than the advisory creator', async () => {
    postgresQueryMock.mockResolvedValueOnce({
      rows: [{ ...pendingAdvisory, actor_id: 'another-owner' }]
    });

    await expect(
      AiAdvisoryService.confirmDecision(
        owner,
        'doc-1',
        'advisory-1',
        'ACCEPTED',
        [{ userId: 'viewer-1', permissionLevel: 'view' }]
      )
    ).rejects.toThrow('Unauthorized: only the advisory creator can confirm this decision');

    expect(permissionMock.grantPermission).not.toHaveBeenCalled();
    expect(auditMock).not.toHaveBeenCalled();
  });

  it('rejects a decision for an advisory that is no longer pending', async () => {
    postgresQueryMock.mockResolvedValueOnce({
      rows: [{ ...pendingAdvisory, status: 'ACCEPTED' }]
    });

    await expect(
      AiAdvisoryService.confirmDecision(
        owner,
        'doc-1',
        'advisory-1',
        'ACCEPTED',
        [{ userId: 'viewer-1', permissionLevel: 'view' }]
      )
    ).rejects.toThrow('This advisory has already been decided');

    expect(permissionMock.grantPermission).not.toHaveBeenCalled();
  });
});
