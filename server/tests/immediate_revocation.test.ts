import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/legacyTestApp';
import { getDatabase } from '../src/db/database';
import { runSeed } from '../src/db/seed';

describe('Immediate Permission Revocation Tests', () => {
  let aliceToken: string;
  let bobToken: string;
  let bobUserId: string;
  let testDocId: string;

  beforeAll(async () => {
    getDatabase();
    runSeed();

    // Authenticate Alice (Owner)
    const aliceRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'alice@trustvault.internal', password: 'AlicePassword123!' });
    aliceToken = aliceRes.body.token;

    // Authenticate Bob (Viewer)
    const bobRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'bob@trustvault.internal', password: 'BobPassword123!' });
    bobToken = bobRes.body.token;
    bobUserId = bobRes.body.user.id;

    // Alice uploads a new test document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${aliceToken}`)
      .field('title', 'Ephemeral Financial Deal Termsheet')
      .field('category', 'Financial')
      .field('classification', 'Confidential')
      .attach('file', Buffer.from('%PDF-1.4\nTermsheet confidential content\n%%EOF'), 'Termsheet.pdf');

    expect(uploadRes.status).toBe(201);
    testDocId = uploadRes.body.document.id;
  });

  it('Step 1: Bob initially has NO access (403 Forbidden)', async () => {
    const res = await request(app)
      .get(`/api/documents/${testDocId}/download`)
      .set('Authorization', `Bearer ${bobToken}`);

    expect(res.status).toBe(403);
  });

  it('Step 2: Alice grants Bob view permission', async () => {
    const grantRes = await request(app)
      .post(`/api/documents/${testDocId}/permissions`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({
        userId: bobUserId,
        permissionLevel: 'view'
      });

    expect(grantRes.status).toBe(201);
    expect(grantRes.body.permission.permission_level).toBe('view');
  });

  it('Step 3: Bob can now view metadata and download file (200 OK)', async () => {
    // Check metadata
    const metaRes = await request(app)
      .get(`/api/documents/${testDocId}`)
      .set('Authorization', `Bearer ${bobToken}`);
    expect(metaRes.status).toBe(200);
    expect(metaRes.body.document.title).toBe('Ephemeral Financial Deal Termsheet');

    // Check download stream
    const downloadRes = await request(app)
      .get(`/api/documents/${testDocId}/download`)
      .set('Authorization', `Bearer ${bobToken}`);
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.headers['content-disposition']).toContain('attachment');
  });

  it('Step 4: Alice revokes Bob access immediately', async () => {
    const revokeRes = await request(app)
      .delete(`/api/documents/${testDocId}/permissions/${bobUserId}`)
      .set('Authorization', `Bearer ${aliceToken}`);

    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.success).toBe(true);
  });

  it('Step 5: Bob is IMMEDIATELY blocked from downloading (403 Forbidden)', async () => {
    // Exactly at the instant of revocation, download fails
    const downloadRes = await request(app)
      .get(`/api/documents/${testDocId}/download`)
      .set('Authorization', `Bearer ${bobToken}`);

    expect(downloadRes.status).toBe(403);
    expect(downloadRes.body.code).toBe('FORBIDDEN');
    expect(downloadRes.body.error).toContain('Access denied');
  });

  it('Step 6: Bob is IMMEDIATELY blocked from viewing metadata (403 Forbidden)', async () => {
    const metaRes = await request(app)
      .get(`/api/documents/${testDocId}`)
      .set('Authorization', `Bearer ${bobToken}`);

    expect(metaRes.status).toBe(403);
    expect(metaRes.body.code).toBe('FORBIDDEN');
  });
});
