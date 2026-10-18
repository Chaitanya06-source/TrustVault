import { v4 as uuidv4 } from 'uuid';
import { getDatabase } from '../db/database';
import { AuditService } from './auditService';
import { AuthService } from './authService';
import { PermissionService } from './permissionService';

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
  /**
   * Analyzes document context and proposes least-privilege access recommendations.
   * NEVER grants or widens access automatically.
   */
  public static generateRecommendation(
    owner: { id: string; email: string; role: string },
    documentTitle: string,
    category: string,
    description: string = '',
    documentId?: string,
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): AiSuggestion {
    const titleAndDesc = `${documentTitle} ${description} ${category}`.toLowerCase();
    const allUsers = AuthService.listUsers().filter(u => u.id !== owner.id);

    let classification: 'Public' | 'Internal' | 'Restricted' | 'Confidential' = 'Internal';
    let sensitivity: 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
    let rationale = '';
    let leakageImpact = '';

    // Sensitive keyword matching & semantic classification
    const isHighlyConfidential = /salary|compensation|payroll|bonus|merger|acquisition|nda|contract|board|audit|lawsuit|legal|secret|private|credential/i.test(titleAndDesc);
    const isInternal = /architecture|roadmap|sprint|spec|guide|process|engineering|technical/i.test(titleAndDesc);

    if (isHighlyConfidential) {
      classification = 'Confidential';
      sensitivity = 'HIGH';
      leakageImpact = 'Severe: Unauthorized exposure may violate regulatory compliance, employment confidentiality, or client non-disclosure agreements.';
      rationale = `Document '${documentTitle}' matches high-sensitivity criteria (${category}). Applying Zero-Trust Principle of Least Privilege: Default deny for all non-essential staff. Recommend restricting view to designated department stakeholders only.`;
    } else if (isInternal) {
      classification = 'Restricted';
      sensitivity = 'MEDIUM';
      leakageImpact = 'Moderate: Internal operational content. Should not be visible to external viewers or unassigned clients.';
      rationale = `Document contains internal engineering or operational plans. Recommend granting 'view' only to active team members, withholding 'edit' permissions to avoid unapproved alterations.`;
    } else {
      classification = 'Internal';
      sensitivity = 'LOW';
      leakageImpact = 'Low: General business documentation.';
      rationale = `Standard corporate document. Access should still be strictly governed by explicit named grants.`;
    }

    // Build suggested recipient list based on least-privilege analysis
    const suggestedRecipients = allUsers.map(u => {
      let recPermission: 'view' | 'edit' | 'none' = 'none';
      let reason = 'Restricted by default under Least Privilege';

      if (isHighlyConfidential) {
        if (u.role === 'owner' || u.email.includes('finance') || u.email.includes('hr') || u.email.includes('alice')) {
          recPermission = 'view';
          reason = 'Stakeholder role requires read-only visibility for compliance/review.';
        } else {
          recPermission = 'none';
          reason = 'Excluded from confidential document to prevent organizational data leakage.';
        }
      } else {
        if (u.role === 'owner' || u.role === 'viewer') {
          recPermission = 'view';
          reason = 'Read-only access suggested for collaborative review.';
        }
      }

      return {
        userId: u.id,
        userName: u.name,
        userEmail: u.email,
        userRole: u.role,
        recommendedPermission: recPermission,
        reason
      };
    });

    const advisoryId = uuidv4();
    const db = getDatabase();
    const now = new Date().toISOString();

    // Store advisory suggestion in database
    db.prepare(`
      INSERT INTO ai_advisory_logs (
        id, document_id, document_title, suggested_classification,
        suggested_recipients_json, security_rationale, actor_id,
        status, created_at
      ) VALUES (
        ?, ?, ?, ?,
        ?, ?, ?,
        'PENDING', ?
      )
    `).run(
      advisoryId,
      documentId || null,
      documentTitle,
      classification,
      JSON.stringify(suggestedRecipients),
      rationale,
      owner.id,
      now
    );

    // Audit the AI suggestion generation
    AuditService.recordEvent({
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

  /**
   * Processes the document owner's explicit decision regarding the AI advisory recommendation.
   * If accepted, grants permissions based on the confirmed recipient list.
   */
  public static confirmDecision(
    owner: { id: string; email: string; role: string },
    documentId: string,
    advisoryId: string,
    decision: 'ACCEPTED' | 'REJECTED' | 'MODIFIED',
    confirmedGrants: Array<{ userId: string; permissionLevel: 'view' | 'edit' }>,
    ipAddress: string = '127.0.0.1',
    userAgent: string = 'client'
  ): { appliedGrantsCount: number } {
    const db = getDatabase();
    const advisory = db
      .prepare('SELECT * FROM ai_advisory_logs WHERE id = ?')
      .get(advisoryId) as any;

    if (!advisory) {
      throw new Error('Advisory record not found');
    }

    if (advisory.actor_id !== owner.id) {
      throw new Error('Only the initiating document owner can confirm this advisory decision');
    }

    const now = new Date().toISOString();
    let appliedCount = 0;

    if (decision === 'ACCEPTED' || decision === 'MODIFIED') {
      for (const grant of confirmedGrants) {
        if (grant.permissionLevel === 'view' || grant.permissionLevel === 'edit') {
          PermissionService.grantPermission(
            documentId,
            owner.id,
            owner.email,
            owner.role,
            grant.userId,
            grant.permissionLevel,
            ipAddress,
            userAgent
          );
          appliedCount++;
        }
      }
    }

    // Update advisory log
    db.prepare(`
      UPDATE ai_advisory_logs
      SET status = ?, confirmed_recipients_json = ?, decided_at = ?
      WHERE id = ?
    `).run(
      decision,
      JSON.stringify(confirmedGrants),
      now,
      advisoryId
    );

    // Audit the human decision
    AuditService.recordEvent({
      actorId: owner.id,
      actorEmail: owner.email,
      actorRole: owner.role,
      action: decision === 'REJECTED' ? 'AI_ADVISORY_REJECTED' : 'AI_ADVISORY_CONFIRMED',
      targetType: 'AI_ADVISORY',
      targetId: advisoryId,
      targetName: advisory.document_title,
      status: 'SUCCESS',
      details: {
        decision,
        documentId,
        appliedGrantsCount: appliedCount
      },
      ipAddress,
      userAgent
    });

    return { appliedGrantsCount: appliedCount };
  }
}
