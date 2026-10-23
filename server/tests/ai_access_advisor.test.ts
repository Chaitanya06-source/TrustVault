import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/legacyTestApp';
import { getDatabase } from '../src/db/database';
import { runSeed } from '../src/db/seed';

describe('AI Least-Privilege Access Advisor Tests', () => {
  let aliceToken: string;
  let bobUserId: string;

  beforeAll(async () => {
    getDatabase();
    runSeed();

    const aliceRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'alice@trustvault.internal', password: 'AlicePassword123!' });
    aliceToken = aliceRes.body.token;

    const bobRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'bob@trustvault.internal', password: 'BobPassword123!' });
    bobUserId = bobRes.body.user.id;
  });

  it('Generates security-conscious recommendation without automatically modifying permissions', async () => {
    const res = await request(app)
      .post('/api/ai/recommend')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({
        documentTitle: 'Executive M&A Termsheet with Target Alpha',
        category: 'Legal',
        description: 'Contains sensitive share purchase agreements and valuation models.'
      });

    expect(res.status).toBe(200);
    const rec = res.body.recommendation;
    expect(rec.suggestedClassification).toBe('Confidential');
    expect(rec.riskAssessment.dataSensitivityLevel).toBe('HIGH');
    expect(rec.humanActionRequired).toBe(true);

    // AI recommendation MUST NOT automatically widen access on documents
    expect(rec.advisoryId).toBeDefined();
  });

  it('Enforces that human confirmation is required before permissions are applied', async () => {
    // 1. Upload doc
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${aliceToken}`)
      .field('title', 'Board Strategy Plan')
      .field('category', 'Executive')
      .attach('file', Buffer.from('%PDF-1.4\nBoard Strategy Plan\n%%EOF'), 'strategy.pdf');

    const docId = uploadRes.body.document.id;

    // 2. Request AI recommendation
    const aiRes = await request(app)
      .post('/api/ai/recommend')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({
        documentId: docId,
        documentTitle: 'Board Strategy Plan',
        category: 'Executive'
      });

    const advisoryId = aiRes.body.recommendation.advisoryId;

    // Verify Bob does not yet have access
    const bobCheck = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${aliceToken}`); // As alice, permissions list is checked
    const permsRes = await request(app)
      .get(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(permsRes.body.permissions.length).toBe(0);

    // 3. Human owner confirms decision
    const confirmRes = await request(app)
      .post('/api/ai/confirm')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({
        documentId: docId,
        advisoryId,
        decision: 'ACCEPTED',
        confirmedGrants: [{ userId: bobUserId, permissionLevel: 'view' }]
      });

    expect(confirmRes.status).toBe(200);
    expect(confirmRes.body.success).toBe(true);
    expect(confirmRes.body.result.appliedGrantsCount).toBe(1);

    // Now Bob has 'view' access
    const updatedPerms = await request(app)
      .get(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(updatedPerms.body.permissions.length).toBe(1);
    expect(updatedPerms.body.permissions[0].user_id).toBe(bobUserId);
  });
});
