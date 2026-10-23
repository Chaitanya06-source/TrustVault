import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/legacyTestApp';
import { getDatabase } from '../src/db/database';
import { runSeed } from '../src/db/seed';

describe('Zero-Trust Document Security Isolation Tests', () => {
  let aliceToken: string; // Document Owner
  let bobToken: string;   // Viewer with specific grants
  let eveToken: string;   // Attacker / ungranted viewer
  let privateDocId: string; // Alice's private doc (no grants)

  beforeAll(async () => {
    getDatabase();
    runSeed();

    // 1. Authenticate Alice (Owner)
    const aliceRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'alice@trustvault.internal', password: 'AlicePassword123!' });
    expect(aliceRes.status).toBe(200);
    aliceToken = aliceRes.body.token;

    // 2. Authenticate Bob (Viewer)
    const bobRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'bob@trustvault.internal', password: 'BobPassword123!' });
    expect(bobRes.status).toBe(200);
    bobToken = bobRes.body.token;

    // 3. Authenticate Eve (Attacker)
    const eveRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'eve@external.org', password: 'EvePassword123!' });
    expect(eveRes.status).toBe(200);
    eveToken = eveRes.body.token;

    // 4. Fetch Alice's private document ID
    const aliceDocs = await request(app)
      .get('/api/documents')
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(aliceDocs.status).toBe(200);

    const privateDoc = aliceDocs.body.documents.find((d: any) =>
      d.title.includes('Board Meeting Minutes')
    );
    expect(privateDoc).toBeDefined();
    privateDocId = privateDoc.id;
  });

  it('Proves an ungranted user CANNOT view metadata of another user private document (returns 403)', async () => {
    const res = await request(app)
      .get(`/api/documents/${privateDocId}`)
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('FORBIDDEN');
    expect(res.body.error).toContain('Access denied');
  });

  it('Proves an ungranted user CANNOT download another user private document bytes (returns 403)', async () => {
    const res = await request(app)
      .get(`/api/documents/${privateDocId}/download`)
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('FORBIDDEN');
    // Ensure zero document bytes were leaked in the response body
    expect(res.headers['content-type']).not.toContain('application/pdf');
  });

  it('Proves search queries DO NOT leak private document existence to unauthorized users', async () => {
    // Eve searches specifically for "Board"
    const res = await request(app)
      .get('/api/documents?q=Board')
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(200);
    expect(res.body.documents.length).toBe(0);
    expect(res.body.total).toBe(0);
  });

  it('Proves an ungranted user CANNOT modify or tamper with another user document', async () => {
    const res = await request(app)
      .put(`/api/documents/${privateDocId}`)
      .set('Authorization', `Bearer ${eveToken}`)
      .send({ title: 'Tampered by Eve' });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('FORBIDDEN');
  });

  it('Proves an ungranted user CANNOT delete another user document', async () => {
    const res = await request(app)
      .delete(`/api/documents/${privateDocId}`)
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('FORBIDDEN');
  });

  it('Proves a viewer CANNOT grant permissions to others on documents they do not own', async () => {
    const res = await request(app)
      .post(`/api/documents/${privateDocId}/permissions`)
      .set('Authorization', `Bearer ${bobToken}`)
      .send({
        userId: '00000000-0000-0000-0000-000000000001',
        permissionLevel: 'view'
      });

    expect(res.status).toBe(403);
    expect(res.body.code).toBe('GRANT_FAILED');
  });

  it('Proves unauthenticated requests without bearer token are universally rejected (returns 401)', async () => {
    const res = await request(app).get(`/api/documents/${privateDocId}/download`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('UNAUTHENTICATED');
  });
});
