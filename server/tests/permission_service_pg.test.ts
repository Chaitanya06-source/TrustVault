import { afterEach, describe, expect, it, vi } from 'vitest';

const { postgresQueryMock, auditMock } = vi.hoisted(() => ({
  postgresQueryMock: vi.fn(),
  auditMock: vi.fn()
}));

vi.mock('../src/db/postgres', () => ({
  postgresQuery: postgresQueryMock
}));

vi.mock('../src/services/auditService.pg', () => ({
  PgAuditService: { recordEvent: auditMock }
}));

import { PgPermissionService } from '../src/services/permissionService.pg';

describe('PostgreSQL permission isolation', () => {
  afterEach(() => {
    postgresQueryMock.mockReset();
    auditMock.mockReset();
  });

  it('allows the document owner to view their document', async () => {
    postgresQueryMock.mockResolvedValueOnce({
      rows: [{ id: 'doc-1', title: 'Private document', owner_id: 'owner-1' }]
    });

    const result = await PgPermissionService.checkAccess(
      'doc-1',
      'owner-1',
      'view'
    );

    expect(result.allowed).toBe(true);
    expect(result.role).toBe('owner');
  });

  it('denies a user with no grant', async () => {
    postgresQueryMock
      .mockResolvedValueOnce({
        rows: [{ id: 'doc-1', title: 'Private document', owner_id: 'owner-1' }]
      })
      .mockResolvedValueOnce({ rows: [] });

    const result = await PgPermissionService.checkAccess(
      'doc-1',
      'stranger-1',
      'view'
    );

    expect(result.allowed).toBe(false);
    expect(result.role).toBe('none');
  });

  it('allows a viewer to view but not edit', async () => {
    postgresQueryMock
      .mockResolvedValueOnce({
        rows: [{ id: 'doc-1', title: 'Private document', owner_id: 'owner-1' }]
      })
      .mockResolvedValueOnce({ rows: [{ permission_level: 'view' }] });

    const viewResult = await PgPermissionService.checkAccess(
      'doc-1',
      'viewer-1',
      'view'
    );

    expect(viewResult.allowed).toBe(true);
    expect(viewResult.role).toBe('viewer');

    postgresQueryMock
      .mockResolvedValueOnce({
        rows: [{ id: 'doc-1', title: 'Private document', owner_id: 'owner-1' }]
      })
      .mockResolvedValueOnce({ rows: [{ permission_level: 'view' }] });

    const editResult = await PgPermissionService.checkAccess(
      'doc-1',
      'viewer-1',
      'edit'
    );

    expect(editResult.allowed).toBe(false);
    expect(editResult.role).toBe('viewer');
  });

  it('denies access immediately after the grant is removed', async () => {
    // First request: grant exists.
    postgresQueryMock
      .mockResolvedValueOnce({
        rows: [{ id: 'doc-1', title: 'Private document', owner_id: 'owner-1' }]
      })
      .mockResolvedValueOnce({ rows: [{ permission_level: 'view' }] });

    const beforeRevocation = await PgPermissionService.checkAccess(
      'doc-1',
      'viewer-1',
      'view'
    );

    expect(beforeRevocation.allowed).toBe(true);

    // Second request: the database no longer contains the grant.
    postgresQueryMock
      .mockResolvedValueOnce({
        rows: [{ id: 'doc-1', title: 'Private document', owner_id: 'owner-1' }]
      })
      .mockResolvedValueOnce({ rows: [] });

    const afterRevocation = await PgPermissionService.checkAccess(
      'doc-1',
      'viewer-1',
      'view'
    );

    expect(afterRevocation.allowed).toBe(false);
  });
});
