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

describe('AI access advisory safety', () => {
  afterEach(() => {
    postgresQueryMock.mockReset();
    auditMock.mockReset();
    permissionMock.checkAccess.mockReset();
    permissionMock.grantPermission.mockReset();
    permissionMock.revokePermission.mockReset();
  });

  it('records a recommendation, requires human action, and does not grant access', async () => {
    postgresQueryMock
      .mockResolvedValueOnce({
        rows: [
          {
            id: 'viewer-1',
            name: 'Viewer One',
            email: 'viewer@example.test',
            role: 'viewer'
          },
          {
            id: 'stranger-1',
            name: 'Stranger',
            email: 'stranger@example.test',
            role: 'user'
          }
        ]
      })
      .mockResolvedValueOnce({ rows: [] });

    auditMock.mockResolvedValueOnce(undefined);

    const suggestion = await AiAdvisoryService.generateRecommendation(
      {
        id: 'owner-1',
        email: 'owner@example.test',
        role: 'owner'
      },
      'Payroll salary records',
      'HR',
      'Confidential employee compensation',
      'doc-1'
    );

    expect(suggestion.humanActionRequired).toBe(true);
    expect(suggestion.suggestedClassification).toBe('Confidential');
    expect(suggestion.suggestedRecipients).toHaveLength(2);

    expect(postgresQueryMock).toHaveBeenCalledTimes(2);
    expect(postgresQueryMock.mock.calls[1][0]).toContain('INSERT INTO ai_advisory_logs');

    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'AI_ADVISORY_SUGGESTION_GENERATED',
        status: 'SUCCESS'
      })
    );

    expect(permissionMock.grantPermission).not.toHaveBeenCalled();
    expect(permissionMock.revokePermission).not.toHaveBeenCalled();
  });
});
