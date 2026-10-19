import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { getDatabase, initSchema } from './database';
import { AuthService } from '../services/authService';
import { DocumentService } from '../services/documentService';
import { PermissionService } from '../services/permissionService';
import { AuditService } from '../services/auditService';
import { CONFIG } from '../config';

export function runSeed(): void {
  console.log('[Seed] Initializing TrustVault database schema...');
  const db = getDatabase();
  initSchema(db);

  // Check if users already exist
  const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
  if (existingUsers && existingUsers.count > 0) {
    console.log('[Seed] Database already seeded. Skipping initial user creation.');
    return;
  }

  console.log('[Seed] Seeding accounts for all roles...');

  const users = [
    {
      id: uuidv4(),
      email: 'admin@trustvault.internal',
      name: 'Audit Administrator',
      password: 'AdminPassword123!',
      role: 'admin' as const
    },
    {
      id: uuidv4(),
      email: 'alice@trustvault.internal',
      name: 'Alice (Finance Director / Owner)',
      password: 'AlicePassword123!',
      role: 'owner' as const
    },
    {
      id: uuidv4(),
      email: 'charlie@trustvault.internal',
      name: 'Charlie (HR Director / Owner)',
      password: 'CharliePassword123!',
      role: 'owner' as const
    },
    {
      id: uuidv4(),
      email: 'bob@trustvault.internal',
      name: 'Bob (Viewer / Analyst)',
      password: 'BobPassword123!',
      role: 'viewer' as const
    },
    {
      id: uuidv4(),
      email: 'eve@external.org',
      name: 'Eve (Unauthorized Attacker)',
      password: 'EvePassword123!',
      role: 'viewer' as const
    }
  ];

  const now = new Date().toISOString();
  const userMap = new Map<string, any>();

  for (const u of users) {
    const passwordHash = AuthService.hashPassword(u.password);
    db.prepare(`
      INSERT INTO users (id, email, name, password_hash, role, is_active, created_at)
      VALUES (?, ?, ?, ?, ?, 1, ?)
    `).run(u.id, u.email, u.name, passwordHash, u.role, now);

    userMap.set(u.email, { id: u.id, email: u.email, role: u.role, name: u.name });

    AuditService.recordEvent({
      actorId: 'system',
      actorEmail: 'system@trustvault.internal',
      actorRole: 'admin',
      action: 'USER_CREATED',
      targetType: 'USER',
      targetId: u.id,
      targetName: u.name,
      status: 'SUCCESS',
      details: { email: u.email, role: u.role }
    });
  }

  console.log('[Seed] Seeding sample secure confidential documents...');

  // Helper to create synthetic valid PDF buffer
  function createPdfBuffer(title: string, content: string): Buffer {
    const pdfContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 120 >>
stream
BT
/F1 12 Tf
72 712 Td
(${title}: ${content}) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000206 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
380
%%EOF`;
    return Buffer.from(pdfContent, 'utf-8');
  }

  // Doc 1: Alice's Private Board Minutes (strictly confidential, no grants)
  const alice = userMap.get('alice@trustvault.internal');
  const bob = userMap.get('bob@trustvault.internal');
  const charlie = userMap.get('charlie@trustvault.internal');

  const doc1 = DocumentService.uploadDocument(
    alice,
    {
      originalname: 'Board_Meeting_Minutes_Strictly_Confidential.pdf',
      buffer: createPdfBuffer('Board Minutes', 'Strictly Confidential: M&A Acquisition Discussions and Valuations'),
      size: 450
    },
    {
      title: 'Q3 Board Meeting Minutes (Strictly Confidential)',
      description: 'Executive committee deliberations on acquisition targets and strategic investments.',
      category: 'Executive',
      classification: 'Confidential'
    }
  );

  // Doc 2: Alice's Contract (shared with Bob with 'view' permission)
  const doc2 = DocumentService.uploadDocument(
    alice,
    {
      originalname: 'Master_Services_Agreement_AcmeCorp.pdf',
      buffer: createPdfBuffer('MSA Acme Corp', 'Master Services Agreement terms, pricing schedules, and indemnity provisions.'),
      size: 480
    },
    {
      title: 'Acme Corp Master Services Agreement',
      description: 'Customer master agreement with negotiated warranty and liability schedules.',
      category: 'Legal',
      classification: 'Restricted'
    }
  );

  // Grant Bob 'view' permission to doc2
  PermissionService.grantPermission(
    doc2.id,
    alice.id,
    alice.email,
    alice.role,
    bob.id,
    'view'
  );

  // Doc 3: Charlie's Salary Letter (Confidential HR, zero external grants)
  const doc3 = DocumentService.uploadDocument(
    charlie,
    {
      originalname: 'Executive_Salary_Bands_2026.pdf',
      buffer: createPdfBuffer('Salary Bands', 'Confidential executive payroll adjustments, equity allocations, and bonus tiers.'),
      size: 510
    },
    {
      title: '2026 Executive Compensation and Equity Bands',
      description: 'Annual executive payroll adjustments, equity allocations, and target bonuses.',
      category: 'HR',
      classification: 'Confidential'
    }
  );

  // Doc 4: Plain text engineering architecture RFC (public/internal)
  const doc4 = DocumentService.uploadDocument(
    alice,
    {
      originalname: 'TrustVault_Architecture_RFC.txt',
      buffer: Buffer.from('RFC-101: Cryptographic Zero-Trust Document Architecture\n1. Zero static URL exposure\n2. Real-time DB permission validation\n3. HMAC-SHA256 hash chaining\n', 'utf-8'),
      size: 150
    },
    {
      title: 'TrustVault Architecture RFC-101',
      description: 'Technical specification of the tamper-evident cryptographic storage and access ledger.',
      category: 'Engineering',
      classification: 'Internal'
    }
  );

  // Grant Bob 'edit' permission to doc4
  PermissionService.grantPermission(
    doc4.id,
    alice.id,
    alice.email,
    alice.role,
    bob.id,
    'edit'
  );

  // Generate an initial unauthorized probe to seed security alert demonstration
  const eve = userMap.get('eve@external.org');
  AuditService.recordEvent({
    actorId: eve.id,
    actorEmail: eve.email,
    actorRole: eve.role,
    action: 'ACCESS_DENIED_DOWNLOAD',
    targetType: 'DOCUMENT',
    targetId: doc1.id,
    targetName: doc1.title,
    status: 'DENIED',
    details: { reason: 'Unauthorized access attempt intercepted by zero-trust gate' },
    ipAddress: '198.51.100.24',
    userAgent: 'curl/7.88.1'
  });

  AuditService.recordEvent({
    actorId: eve.id,
    actorEmail: eve.email,
    actorRole: eve.role,
    action: 'ACCESS_DENIED_VIEW',
    targetType: 'DOCUMENT',
    targetId: doc3.id,
    targetName: doc3.title,
    status: 'DENIED',
    details: { reason: 'Probing confidential HR document without permission' },
    ipAddress: '198.51.100.24',
    userAgent: 'Mozilla/5.0 SecurityScanner'
  });

  console.log('[Seed] Database seeding completed successfully.');
  console.log('Available Accounts:');
  console.log('  Admin:   admin@trustvault.internal   / AdminPassword123!');
  console.log('  Owner:   alice@trustvault.internal   / AlicePassword123!');
  console.log('  Owner:   charlie@trustvault.internal / CharliePassword123!');
  console.log('  Viewer:  bob@trustvault.internal     / BobPassword123!');
  console.log('  Attacker: eve@external.org           / EvePassword123!');
}

if (require.main === module) {
  runSeed();
}
