import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, ChevronRight, Lock, Key, Server, Database, FileCheck } from 'lucide-react';

interface ThreatItem {
  id: string;
  category: 'IDOR' | 'Authentication' | 'Storage' | 'Audit' | 'Permissions' | 'Injection' | 'AI';
  title: string;
  attackVector: string;
  threatSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  defenseImplementation: string;
  acceptedRisk?: string;
  testedIn: string;
}

const THREATS_DATA: ThreatItem[] = [
  {
    id: 'T-01',
    category: 'IDOR',
    title: 'Insecure Direct Object Reference (IDOR) on File Downloads',
    attackVector: 'Attacker guesses or enumerates document UUID in GET /api/documents/:id/download without holding active permission.',
    threatSeverity: 'CRITICAL',
    defenseImplementation: 'Server executes real-time SQL JOIN against document_permissions table right before opening byte stream. Static file paths are never exposed.',
    testedIn: 'server/tests/security_isolation.test.ts'
  },
  {
    id: 'T-02',
    category: 'Permissions',
    title: 'Pre-Signed URL & Caching Bypass on Revocation (Window of Vulnerability)',
    attackVector: 'Using long-lived S3 pre-signed URLs or browser disk caches: after an owner revokes access, the previous link or cache still yields bytes.',
    threatSeverity: 'CRITICAL',
    defenseImplementation: 'Zero pre-signed URLs. All byte streams flow through application server with Cache-Control: no-store and instant DB permission check.',
    testedIn: 'server/tests/immediate_revocation.test.ts'
  },
  {
    id: 'T-03',
    category: 'Audit',
    title: 'Rogue Administrator or Attacker Quietly Altering Audit History',
    attackVector: 'Attacker accesses raw database and modifies or deletes log rows to hide evidence of unauthorized access.',
    threatSeverity: 'CRITICAL',
    defenseImplementation: 'Cryptographic HMAC-SHA256 sequential hash chaining. Any modification, reordering, or deletion breaks the Merkle-like chain immediately.',
    testedIn: 'server/tests/audit_trail_tamper_detection.test.ts'
  },
  {
    id: 'T-04',
    category: 'Audit',
    title: 'Unrecorded Refusal Attempts (Covert Reconnaissance)',
    attackVector: 'Attacker probes document IDs; failed 403/404 attempts are discarded by server, leaving security teams blind to probing.',
    threatSeverity: 'HIGH',
    defenseImplementation: 'All denied attempts (ACCESS_DENIED_VIEW, ACCESS_DENIED_DOWNLOAD) are chained into the audit ledger with actor, IP, and timestamp before returning 403.',
    testedIn: 'server/tests/audit_trail_tamper_detection.test.ts'
  },
  {
    id: 'T-05',
    category: 'Storage',
    title: 'Path Traversal via Malicious Filenames (../../etc/passwd)',
    attackVector: 'Uploaded multipart filename contains directory traversal sequences attempting to overwrite system files.',
    threatSeverity: 'HIGH',
    defenseImplementation: 'Filenames are strictly sanitized with regex stripping paths and control chars. On disk, files are stored strictly by UUID in an isolated vault.',
    testedIn: 'server/tests/upload_validation.test.ts'
  },
  {
    id: 'T-06',
    category: 'Storage',
    title: 'MIME Confusion / File Masking (Disguised PE/ELF Executable)',
    attackVector: 'Attacker uploads an executable or script disguised with a .pdf or .png extension.',
    threatSeverity: 'HIGH',
    defenseImplementation: 'Deep magic byte inspection: reads the first 512 bytes to verify magic headers (%PDF, PNG, etc.) and rejects Windows MZ / Linux ELF headers.',
    testedIn: 'server/tests/upload_validation.test.ts'
  },
  {
    id: 'T-07',
    category: 'Authentication',
    title: 'Timing Attacks on Password and Token Verification',
    attackVector: 'Attacker measures response latency to deduce password prefix matches or detect existing user emails.',
    threatSeverity: 'MEDIUM',
    defenseImplementation: 'Uses scrypt with constant-time crypto.timingSafeEqual comparison and dummy hash calculation for missing users.',
    testedIn: 'server/tests/security_isolation.test.ts'
  },
  {
    id: 'T-08',
    category: 'AI',
    title: 'Autonomous AI Permission Escalation / Hallucination',
    attackVector: 'AI access advisor hallucinates or autonomously widens access permissions to sensitive documents without human authorization.',
    threatSeverity: 'HIGH',
    defenseImplementation: 'AI is strictly advisory. Machine can never execute grants on its own. Explicit human confirmation is required and audited.',
    testedIn: 'server/tests/ai_access_advisor.test.ts'
  },
  {
    id: 'T-09',
    category: 'Permissions',
    title: 'Horizontal Privilege Escalation (Viewer Granting Access to Third Parties)',
    attackVector: 'A viewer with read access attempts to call POST /api/documents/:id/permissions to share document with unauthorized users.',
    threatSeverity: 'HIGH',
    defenseImplementation: 'Permission service explicitly checks that grantor is the document owner (owner_id === requester.id). Non-owners are denied with 403.',
    testedIn: 'server/tests/security_isolation.test.ts'
  },
  {
    id: 'T-10',
    category: 'Storage',
    title: 'Cross-Site Scripting (XSS) via Browser In-Line Execution',
    attackVector: 'Attacker uploads SVG or HTML with embedded script tag, attempting to execute malicious JavaScript in browser context.',
    threatSeverity: 'HIGH',
    defenseImplementation: 'Server serves downloads with Content-Disposition: attachment, X-Content-Type-Options: nosniff, and Content-Security-Policy: default-src none.',
    testedIn: 'server/tests/security_isolation.test.ts'
  }
];

export const ThreatModelPage: React.FC = () => {
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  const filtered = selectedCategory === 'ALL'
    ? THREATS_DATA
    : THREATS_DATA.filter(t => t.category === selectedCategory);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">TrustVault Threat Matrix & STRIDE Model</h1>
          <p className="text-sm text-slate-400 mt-1">
            Exhaustive defense implementation against penetration attempts, permission bypasses, and audit tampering.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-lg text-xs font-mono font-semibold">
            10 Attack Vectors Modeled & Defended
          </span>
        </div>
      </div>

      {/* Category Filter */}
      <div className="flex items-center gap-1.5 overflow-x-auto text-xs pb-1">
        {['ALL', 'IDOR', 'Permissions', 'Audit', 'Storage', 'Authentication', 'AI'].map(cat => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded-lg font-medium transition ${
              selectedCategory === cat
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Threat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map(t => (
          <div
            key={t.id}
            className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-3 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="font-mono text-xs font-bold text-slate-400">{t.id}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                  t.threatSeverity === 'CRITICAL'
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                }`}>
                  {t.threatSeverity}
                </span>
              </div>

              <h3 className="text-sm font-semibold text-white leading-snug">{t.title}</h3>

              <div className="mt-2.5 text-xs text-slate-400 space-y-1.5">
                <div>
                  <strong className="text-slate-300">Attack Vector:</strong> {t.attackVector}
                </div>
                <div className="p-2.5 bg-slate-950/70 border border-slate-800/80 rounded-lg text-emerald-300/90">
                  <strong className="text-emerald-400">Mitigation:</strong> {t.defenseImplementation}
                </div>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
              <span className="flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Verified in:</span>
              </span>
              <span className="text-slate-400 truncate max-w-[220px]" title={t.testedIn}>
                {t.testedIn.split('/').pop()}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
