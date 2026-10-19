import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/app';
import { getDatabase } from '../src/db/database';
import { runSeed } from '../src/db/seed';

describe('File Upload Validation & Path Traversal Defense Tests', () => {
  let aliceToken: string;

  beforeAll(async () => {
    getDatabase();
    runSeed();

    const aliceRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'alice@trustvault.internal', password: 'AlicePassword123!' });
    aliceToken = aliceRes.body.token;
  });

  it('Blocks disguised executable disguised as a PDF (MIME Spoofing / Magic Bytes test)', async () => {
    // Windows PE executable header: 'MZ' (0x4D, 0x5A)
    const fakePdfPayload = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);

    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${aliceToken}`)
      .field('title', 'Trojan Invoice')
      .field('category', 'Financial')
      .attach('file', fakePdfPayload, 'invoice.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Security alert: Windows executable');
  });

  it('Blocks disallowed executable file extensions (.exe)', async () => {
    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${aliceToken}`)
      .field('title', 'Malware Script')
      .field('category', 'Engineering')
      .attach('file', Buffer.from('echo malicious'), 'exploit.exe');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not permitted');
  });

  it('Sanitizes dangerous path traversal filenames (../../etc/passwd.pdf)', async () => {
    const validPdfPayload = Buffer.from('%PDF-1.4\nValid PDF body\n%%EOF');

    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${aliceToken}`)
      .field('title', 'Path Traversal Probe')
      .field('category', 'Legal')
      .attach('file', validPdfPayload, '../../../../etc/passwd.pdf');

    expect(res.status).toBe(201);
    // Filename must NOT retain directory traversal segments
    expect(res.body.document.original_filename).not.toContain('..');
    expect(res.body.document.original_filename).not.toContain('/');
    expect(res.body.document.original_filename).not.toContain('\\');
  });
});
