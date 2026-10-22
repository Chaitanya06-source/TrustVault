import { v4 as uuidv4 } from 'uuid';
import { postgresQuery } from '../db/postgres';
import { PgAuditService } from './auditService.pg';
import { PgPermissionService } from './permissionService.pg';

type UserRole = 'admin' | 'owner' | 'viewer';
type PermissionLevel = 'view' | 'edit';
type Decision = 'ACCEPTED' | 'REJECTED' | 'MODIFIED';

interface AdvisoryOwner {
  id: string;
  email: string;
  role: string;
}

interface UserRow {
  id: string;
  name: string;
  email: string;
  role: string;
}

interface AdvisoryRow {
  id: string;
  document_id: string | null;
  document_title: string;
  actor_id: string;
  status: string;
}

export interface AiSuggestion {
  advisoryId: string;
  documentId?: string;
  documentTitle: string;
  suggestedClassification: 'Public' | 'Internal' | 'Restricted' | 'Confidential';
  suggestedRecipients: Array<{
    userId: string;
    userName: string;
    userEmail: string;
    userRole: string;
    recommendedPermission: 'view' | 'edit' | 'none';
    reason: string;
  }>;
  securityRationale: string;
  riskAssessment: {
    dataSensitivityLevel: 'HIGH' | 'MEDIUM' | 'LOW';
    leakageImpact: string;
    strictZeroTrustRecommended: boolean;
  };
  humanActionRequired: boolean;
}

export class AiAdvisoryService {
  public static async generateRecommendation(
    owner: AdvisoryOwner,
    documentTitle: string,
    category: string,
    description = '',
    documentId?: string,
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<AiSuggestion> {
    const usersResult = await postgresQuery<UserRow>(
      `SELECT id, name, email, role
       FROM users
       WHERE is_active = 1 AND id <> $1
       ORDER BY name ASC`,
      [owner.id]
    );

    const allUsers = usersResult.rows;
    const titleAndDesc =
      `${documentTitle} ${description} ${category}`.toLowerCase();

    let classification: AiSuggestion['suggestedClassification'] = 'Internal';
    let sensitivity: 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
    let leakageImpact = 'Low: General business documentation.';
    let rationale = 'Standard corporate document. Access should still be strictly governed by explicit named grants.';

    const isHighlyConfidential =
      /salary|compensation|payroll|bonus|merger|acquisition|nda|contract|board|audit|lawsuit|legal|secret|private|credential/i.test(titleAndDesc);

    const isInternal =
      /architecture|roadmap|sprint|spec|guide|process|engineering|technical/i.test(titleAndDesc);

    if (isHighlyConfidential) {
      classification = 'Confidential';
      sensitivity = 'HIGH';
      leakageImpact = 'Severe: Unauthorized exposure may violate regulatory compliance, employment confidentiality, or client non-disclosure agreements.';
      rationale = `Document '${documentTitle}' matches high-sensitivity criteria (${category}). Applying Zero-Trust Principle of Least Privilege: Default deny for all non-essential staff. Recommend restricting view to designated department stakeholders only.`;
    } else if (isInternal) {
      classification = 'Restricted';
      sensitivity = 'MEDIUM';
      leakageImpact = 'Moderate: Internal operational content. Should not be visible to external viewers or unassigned clients.';
      rationale = "Document contains internal engineering or operational plans. Recommend granting 'view' only to active team members, withholding 'edit' permissions to avoid unapproved alterations.";
    }

    const suggestedRecipients = allUsers.map((user) => {
      let recommendedPermission: 'view' | 'edit' | 'none' = 'none';
      let reason = 'Restricted by default under Least Privilege';

      if (isHighlyConfidential) {
        if (
          user.role === 'owner' ||
          /finance|hr|alice/i.test(user.email)
        ) {
          recommendedPermission = 'view';
          reason = 'Stakeholder role requires read-only visibility for compliance/review.';
        } else {
          reason = 'Excluded from confidential document to prevent organizational data leakage.';
        }
      } else if (user.role === 'owner' || user.role === 'viewer') {
        recommendedPermission = 'view';
        reason = 'Read-only access suggested for collaborative review.';
      }

      return {
        userId: user.id,
        userName: user.name,
        userEmail: user.email,
        userRole: user.role,
        recommendedPermission,
        reason
      };
    });

    const advisoryId = uuidv4();
    const createdAt = new Date().toISOString();

    await postgresQuery(
      `INSERT INTO ai_advisory_logs (
        id, document_id, document_title, suggested_classification,
        suggested_recipients_json, security_rationale, actor_id,
        status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', $8)`,
      [
        advisoryId,
        documentId || null,
        documentTitle,
        classification,
        JSON.stringify(suggestedRecipients),
        rationale,
        owner.id,
        createdAt
      ]
    );

    await PgAuditService.recordEvent({
      actorId: owner.id,
      actorEmail: owner.email,
      actorRole: owner.role,
      action: 'AI_ADVISORY_SUGGESTION_GENERATED',
      targetType: 'AI_ADVISORY',
      targetId: advisoryId,
      targetName: documentTitle,
      status: 'SUCCESS',
      details: {
        suggestedClassification: classification,
        sensitivityLevel: sensitivity,
        rationale
      },
      ipAddress,
      userAgent
    });

    return {
      advisoryId,
      documentId,
      documentTitle,
      suggestedClassification: classification,
      suggestedRecipients,
      securityRationale: rationale,
      riskAssessment: {
        dataSensitivityLevel: sensitivity,
        leakageImpact,
        strictZeroTrustRecommended: true
      },
      humanActionRequired: true
    };
  }

  public static async confirmDecision(
    owner: AdvisoryOwner,
    documentId: string,
    advisoryId: string,
    decision: Decision,
    confirmedGrants: Array<{ userId: string; permissionLevel: PermissionLevel }>,
    ipAddress = '127.0.0.1',
    userAgent = 'client'
  ): Promise<{ appliedGrantsCount: number }> {
    const advisoryResult = await postgresQuery<AdvisoryRow>(
      `SELECT id, document_id, document_title, actor_id, status
       FROM ai_advisory_logs
       WHERE id = $1`,
      [advisoryId]
    );

    const advisory = advisoryResult.rows[0];

    if (!advisory) {
      throw new Error('AI advisory not found');
    }

    if (advisory.actor_id !== owner.id) {
      throw new Error('Unauthorized: only the advisory creator can confirm this decision');
    }

    if (advisory.document_id && advisory.document_id !== documentId) {
      throw new Error('The document does not match this advisory');
    }

    if (advisory.status !== 'PENDING') {
      throw new Error('This advisory has already been decided');
    }

    let appliedGrantsCount = 0;

    if (decision === 'ACCEPTED' || decision === 'MODIFIED') {
      for (const grant of confirmedGrants) {
        await PgPermissionService.grantPermission(
          documentId,
          owner.id,
          owner.email,
          owner.role,
          grant.userId,
          grant.permissionLevel,
          ipAddress,
          userAgent
        );
        appliedGrantsCount++;
      }
    }

    const decidedAt = new Date().toISOString();

    await postgresQuery(
      `UPDATE ai_advisory_logs
       SET status = $1, confirmed_recipients_json = $2, decided_at = $3
       WHERE id = $4 AND status = 'PENDING'`,
      [
        decision,
        JSON.stringify(
          decision === 'REJECTED' ? [] : confirmedGrants
        ),
        decidedAt,
        advisoryId
      ]
    );

    await PgAuditService.recordEvent({
      actorId: owner.id,
      actorEmail: owner.email,
      actorRole: owner.role,
      action: decision === 'REJECTED'
        ? 'AI_ADVISORY_REJECTED'
        : 'AI_ADVISORY_CONFIRMED',
      targetType: 'AI_ADVISORY',
      targetId: advisoryId,
      targetName: advisory.document_title,
      status: 'SUCCESS',
      details: {
        decision,
        documentId,
        appliedGrantsCount
      },
      ipAddress,
      userAgent
    });

    return { appliedGrantsCount };
  }
}
