import { v4 as uuidv4 } from 'uuid';
import { postgresQuery } from './postgres';
import { PgAuthService } from '../services/authService.pg';
import { DocumentService } from '../services/documentService.pg';
import { PgPermissionService } from '../services/permissionService.pg';
import { PgAuditService } from '../services/auditService.pg';

async function runSeed(): Promise<void> {
  const existing = await postgresQuery<{ count: string }>(
    'SELECT COUNT(*)::text AS count FROM users'
  );

  if (Number(existing.rows[0]?.count ?? 0) > 0) {
    console.log('Seed skipped: PostgreSQL already contains users.');
    return;
  }

  const demoUsers = [
    { email: 'admin@trustvault.internal', name: 'Audit Administrator', password: 'AdminPassword123!', role: 'admin' },
    { email: 'alice@trustvault.internal', name: 'Alice (Finance Director / Owner)', password: 'AlicePassword123!', role: 'owner' },
    { email: 'charlie@trustvault.internal', name: 'Charlie (HR Director / Owner)', password: 'CharliePassword123!', role: 'owner' },
    { email: 'bob@trustvault.internal', name: 'Bob (Viewer / Analyst)', password: 'BobPassword123!', role: 'viewer' },
    { email: 'eve@external.org', name: 'Eve (Unauthorized Attacker)', password: 'EvePassword123!', role: 'viewer' },
  ] as const;

  const users: Record<string, { id: string; email: string; name: string; role: string }> = {};

  for (const item of demoUsers) {
    const id = uuidv4();
    const createdAt = new Date().toISOString();

    await postgresQuery(
      `INSERT INTO users (id, email, name, password_hash, role, is_active, created_at)
       VALUES ($1, $2, $3, $4, $5, 1, $6)`,
      [id, item.email, item.name, PgAuthService.hashPassword(item.password), item.role, createdAt]
    );

    users[item.email] = { id, email: item.email, name: item.name, role: item.role };

    await PgAuditService.recordEvent({
      actorId: id,
      actorEmail: item.email,
      actorRole: item.role,
      action: 'USER_CREATED',
      targetType: 'USER',
      targetId: id,
      targetName: item.name,
      status: 'SUCCESS',
      details: { seeded: true },
    });
  }

  const alice = users['alice@trustvault.internal'];
  const charlie = users['charlie@trustvault.internal'];
  const bob = users['bob@trustvault.internal'];

  const makePdf = (content: string): Buffer =>
    Buffer.from(
      `%PDF-1.4\n% TrustVault demo document\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% ${content}\n%%EOF`,
      'utf8'
    );

  const doc1 = await DocumentService.uploadDocument(
    alice,
    { originalname: 'board-minutes.pdf', buffer: makePdf('Board meeting minutes'), size: makePdf('Board meeting minutes').length },
    { title: 'Q4 Board Meeting Minutes', description: 'Confidential board discussion notes', category: 'Finance', classification: 'Confidential' }
  );

  const doc2 = await DocumentService.uploadDocument(
    alice,
    { originalname: 'acme-contract.pdf', buffer: makePdf('Acme contract'), size: makePdf('Acme contract').length },
    { title: 'Acme Corp Contract', description: 'Customer contract and commercial terms', category: 'Legal', classification: 'Internal' }
  );

  await PgPermissionService.grantPermission(doc2.id, alice.id, alice.email, alice.role, bob.id, 'view');

  await DocumentService.uploadDocument(
    charlie,
    { originalname: 'salary-letter.pdf', buffer: makePdf('Salary letter'), size: makePdf('Salary letter').length },
    { title: 'Salary Revision Letter', description: 'Restricted HR compensation document', category: 'HR', classification: 'Confidential' }
  );

  const doc4 = await DocumentService.uploadDocument(
    alice,
    { originalname: 'architecture-rfc.pdf', buffer: makePdf('TrustVault architecture RFC'), size: makePdf('TrustVault architecture RFC').length },
    { title: 'TrustVault Architecture RFC', description: 'Technical architecture and design decisions', category: 'Engineering', classification: 'Internal' }
  );

  await PgPermissionService.grantPermission(doc4.id, alice.id, alice.email, alice.role, bob.id, 'edit');

  for (const document of [doc1, doc4]) {
    await PgAuditService.recordEvent({
      actorId: users['eve@external.org'].id,
      actorEmail: users['eve@external.org'].email,
      actorRole: users['eve@external.org'].role,
      action: 'ACCESS_DENIED',
      targetType: 'DOCUMENT',
      targetId: document.id,
      targetName: document.title,
      status: 'DENIED',
      details: { reason: 'Seeded demonstration of unauthorized access' },
    });
  }

  console.log('PostgreSQL demo seed completed.');
  console.log('Demo accounts:');
  for (const item of demoUsers) {
    console.log(`  ${item.email} / ${item.password} (${item.role})`);
  }
}

runSeed().catch((error: unknown) => {
  console.error('PostgreSQL seed failed:', error);
  process.exitCode = 1;
});
