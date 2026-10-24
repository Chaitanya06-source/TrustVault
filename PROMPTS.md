# TrustVault AI Collaboration & Security Oversight Log (PROMPTS.md)

This file records AI-assisted development decisions and problems discovered during the TrustVault sprint. The dates refer to development events/commits where those changes were made. This document itself was consolidated later in the sprint; it is not proof that each paragraph was written contemporaneously. Where an AI output was reconstructed from the resulting code/design discussion rather than preserved verbatim, it is a prompt summary, not a verbatim transcript.

---

## Reusable System Context & Security Instructions

Across the 7-day sprint, the following security constraints were enforced as the base system prompt for all architectural and code generation prompts:

```text
[SYSTEM SECURITY INSTRUCTION]:
1. Zero-Trust Access Gateway: Every read, write, download, and metadata request must be validated at the database layer. Never trust client-side state or route guards.
2. Immediate Revocation Invariant: When an owner revokes access, all subsequent requests must fail immediately (zero-latency revocation). No long-lived pre-signed bypass tokens.
3. Tamper-Evident Ledger: Audit records must be cryptographically chained using HMAC-SHA256. Quiet alteration or deletion must be mathematically provable and detectable.
4. Refusal Logging: Every rejected or unauthorized access attempt must be recorded in the audit trail before returning HTTP 403/404.
5. AI Access Guardrail: AI may suggest least-privilege policies, but must NEVER autonomously grant or widen permissions without explicit human confirmation.
```

---

## Log Entries

### Entry 1: Pre-Signed URLs vs. Real-Time Revocation Enforcement
* **Date**: October 14, 2026
* **Component**: Document Download & File Delivery Engine
* **Prompt Summary**:
  > *"Design a scalable file storage and download mechanism for TrustVault where users can download large confidential documents securely."*
* **What the AI Produced**:
  The AI generated a service utilizing AWS S3 pre-signed URLs with a 15-minute expiration:
  ```typescript
  // AI-generated flawed code:
  export async function getDownloadUrl(documentId: string, userId: string) {
    const hasPermission = await checkUserPermission(documentId, userId);
    if (!hasPermission) throw new Error("Forbidden");
    // Generate S3 presigned URL valid for 15 minutes
    return s3.getSignedUrlPromise('getObject', {
      Bucket: 'trustvault-docs',
      Key: documentId,
      Expires: 900 // 15 minutes
    });
  }
  ```
* **What Was Wrong With It (Specifically)**:
  **Violates Non-Negotiable Requirement #3: Taking access away works immediately.**
  If Alice grants Bob access to an M&A document at 10:00, Bob generates a pre-signed URL at 10:01. At 10:02, Alice discovers Bob is leaving the company and revokes his access in the database. Because the pre-signed URL was cryptographically signed by AWS IAM credentials and cached for 15 minutes, Bob can continue to download the document directly from S3 until 10:16! The application database revocation has zero effect on the in-flight URL.
* **What We Did Instead**:
  We rejected pre-signed S3 URLs entirely. All file downloads must stream directly through the application server controller (`GET /api/documents/:id/download`). The server executes a live SQL permission query against `document_permissions` on the HTTP request, and sets `Cache-Control: no-store, no-cache, must-revalidate, private` to prevent reverse-proxy and browser caching.
* **Code Reference & Commit**: Fixed in Commit [`bc8a758`](https://github.com/Chaitanya06-source/TrustVault/commit/bc8a75897f51c9524dce04c64677ced32ca49605) (`feat(auth): implement zero-trust authorization gateway and real-time instant revocation`) and [`fe41bbc`](https://github.com/Chaitanya06-source/TrustVault/commit/fe41bbc495c5f757ccbef4c5950f4880ca3ac505). Code: `server/src/services/documentService.ts` and `server/tests/immediate_revocation.test.ts`.

---

### Entry 2: Audit Trail Architecture (Simple SQL Append vs. Cryptographic Hash Chain)
* **Date**: October 15, 2026
* **Component**: Audit Logging & Non-Repudiation Subsystem
* **Prompt Summary**:
  > *"Implement the audit trail schema and service to record document uploads, downloads, views, and permission grants."*
* **What the AI Produced**:
  The AI suggested a standard relational database table:
  ```sql
  CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id TEXT,
    action TEXT,
    document_id TEXT
  );
  ```
  With a standard `INSERT INTO audit_logs VALUES (...)` query.
* **What Was Wrong With It (Specifically)**:
  **Violates Non-Negotiable Requirement #2: An audit trail that can be quietly altered is not evidence.**
  If a malicious insider, compromised admin account, or SQL injection vulnerability modifies a row (`UPDATE audit_logs SET user_id = 'innocent' WHERE document_id = 'leak-123'`) or deletes rows (`DELETE FROM audit_logs WHERE action = 'DOCUMENT_DOWNLOAD'`), the database offers zero proof of tampering. The record could be altered quietly and nobody could prove it afterwards.
* **What We Did Instead**:
  We designed an append-only cryptographic HMAC-SHA256 sequential hash chain (not a Merkle tree). Production verification status: the deployed audit verifier has reported a hash mismatch at record 1. This remains unresolved and does not, by itself, prove tampering. Each record contains `sequence_number`, `prev_hash`, and a cryptographic `record_hash` computed via `HMAC-SHA256(secret_salt, `${sequence}|${timestamp}|${actor}|${action}|${target}|${status}|${details}|${prev_hash}`)`.
  We also wrote a verification algorithm `AuditService.verifyChainIntegrity()` that recalculates the entire ledger and flags any broken link or altered byte down to the exact block index.
* **Code Reference & Commit**: Fixed in Commit [`336a6cf`](https://github.com/Chaitanya06-source/TrustVault/commit/336a6cf509aba6aa06db577231b0e622394faa13) (`feat(audit): implement cryptographic HMAC-SHA256 tamper-evident hash chain ledger`). Code: `server/src/services/auditService.ts` and `server/tests/audit_trail_tamper_detection.test.ts`.

---

### Entry 3: Silent Discard of Refused Access Attempts
* **Date**: October 16, 2026
* **Component**: Authorization Middleware & Intrusion Detection
* **Prompt Summary**:
  > *"Write an Express authorization middleware that checks if the requesting user has view or edit permission before calling next()."*
* **What the AI Produced**:
  ```typescript
  // AI-generated flawed middleware:
  export function checkDocAccess(req, res, next) {
    const { id } = req.params;
    const userId = req.user.id;
    const hasAccess = db.prepare('SELECT 1 FROM document_permissions WHERE document_id = ? AND user_id = ?').get(id, userId);
    if (!hasAccess) {
      return res.status(403).json({ error: "Access denied" });
    }
    next();
  }
  ```
* **What Was Wrong With It (Specifically)**:
  **Violates Requirement: Refused and unauthorized attempts must be provably recorded.**
  When unauthorized user Eve probed confidential documents, the middleware rejected the request with 403, but *logged nothing*. An attacker could run automated port and IDOR scanners against TrustVault without leaving any trace in the audit ledger. The security team and auditors would have zero evidence of reconnaissance.
* **What We Did Instead**:
  We modified the authorization pipeline so that whenever access evaluation fails (`access.allowed === false`), an `ACCESS_DENIED_VIEW` or `ACCESS_DENIED_DOWNLOAD` event is atomically chained into the cryptographic audit ledger with the offending actor's ID, email, IP address, user-agent, and timestamp *before* transmitting the HTTP 403 Forbidden response.
* **Code Reference & Commit**: Fixed in Commit [`bc8a758`](https://github.com/Chaitanya06-source/TrustVault/commit/bc8a75897f51c9524dce04c64677ced32ca49605) (`feat(auth): implement zero-trust authorization gateway and real-time instant revocation`) and [`fe41bbc`](https://github.com/Chaitanya06-source/TrustVault/commit/fe41bbc495c5f757ccbef4c5950f4880ca3ac505). Code: `server/src/services/documentService.ts` and `server/tests/audit_trail_tamper_detection.test.ts`.

---

### Entry 4: File Upload Validation (Client MIME Header vs. Deep Magic Bytes)
* **Date**: October 17, 2026
* **Component**: Upload Validation & Malware Defense Gateway
* **Prompt Summary**:
  > *"Write validation logic for uploaded documents to ensure only valid PDFs, Word documents, and spreadsheets are accepted."*
* **What the AI Produced**:
  ```typescript
  // AI-generated flawed validation:
  const allowedMimes = ['application/pdf', 'application/msword'];
  if (!allowedMimes.includes(file.mimetype)) {
    throw new Error("Invalid file type");
  }
  ```
* **What Was Wrong With It (Specifically)**:
  **MIME Confusion / Extension Spoofing Vulnerability.**
  `file.mimetype` is populated directly from the client's HTTP request header (`Content-Type: application/pdf`). An attacker can upload a Windows PE binary executable (`evil.exe`), a Linux ELF script, or a webshell, name it `invoice.pdf`, and set the HTTP header to `application/pdf`. The AI's validation passed the file through unconditionally, saving a disguised executable into storage.
* **What We Did Instead**:
  We engineered `FileService.validateMagicBytes()` to inspect the raw binary header bytes:
  - Validates that `.pdf` files begin with `%PDF` (0x25 0x50 0x44 0x46)
  - Validates that OpenXML (.docx, .xlsx) files begin with the ZIP container signature `PK\x03\x04`
  - Explicitly rejects any file containing Windows PE (`MZ` 0x4D 0x5A) or Linux ELF (`\x7fELF`) binary signatures, regardless of claimed extension or MIME header.
  - Sanitizes filenames against path traversal sequences (`../../etc/passwd`).
* **Code Reference & Commit**: Fixed in Commit [`fe41bbc`](https://github.com/Chaitanya06-source/TrustVault/commit/fe41bbc495c5f757ccbef4c5950f4880ca3ac505) (`feat(storage): implement secure vault storage with binary magic-byte validation and traversal defense`). Code: `server/src/services/fileService.ts` and `server/tests/upload_validation.test.ts`.

---

### Entry 5: Autonomous AI Permission Granting
* **Date**: October 18, 2026
* **Component**: AI Access Advisor & Permission Recommender
* **Prompt Summary**:
  > *"Add an AI feature that reads the document category and automatically grants access to the appropriate departments."*
* **What the AI Produced**:
  The AI proposed an autonomous function that directly modified the database:
  ```typescript
  // AI-generated flawed autonomous grant:
  export async function autoAssignPermissions(docId: string, category: string) {
    if (category === 'Financial') {
      const financeUsers = await getFinanceUsers();
      for (const u of financeUsers) {
        await db.grantPermission(docId, u.id, 'view'); // Autonomous write!
      }
    }
  }
  ```
* **What Was Wrong With It (Specifically)**:
  **Violates Core Requirement: 'The machine must never widen access on its own. A person confirms, and both the suggestion and the decision go into the audit.'**
  Allowing an AI model to autonomously insert rows into `document_permissions` violates Zero-Trust principles. If an AI hallucinates or misclassifies an executive compensation letter as general financial documentation, it could accidentally expose executive salaries to junior analysts without human oversight.
* **What We Did Instead**:
  We designed `AiAdvisoryService` as a strictly read-only advisor:
  1. The AI generates an advisory proposal with sensitivity analysis and security rationale.
  2. The proposal is saved as `PENDING` and audited (`AI_ADVISORY_SUGGESTION_GENERATED`).
  3. The owner must manually review the suggested recipients in the UI and click "Confirm".
  4. Only upon explicit human confirmation are grants applied, and the human confirmation is audited (`AI_ADVISORY_CONFIRMED`).
* **Code Reference & Commit**: Fixed in Commit [`2b2fb2c`](https://github.com/Chaitanya06-source/TrustVault/commit/2b2fb2c43413e9ffac1f38a6555989a99ddee624) (`feat(ai): integrate AI access advisor with mandatory human confirmation and audit recording`). Code: `server/src/services/aiAdvisoryService.ts` and `server/tests/ai_access_advisor.test.ts`.

---

## Summary of AI Flaws Identified and Fixed

| Focus Area | Confident AI Proposal | Real-World Security Risk | TrustVault Engineering Resolution | Commit |
| :--- | :--- | :--- | :--- | :--- |
| **Revocation** | 15-minute S3 pre-signed URLs | Revocation does not invalidate in-flight URLs | Application-layer byte proxy with instant real-time DB check | [`bc8a758`](https://github.com/Chaitanya06-source/TrustVault/commit/bc8a75897f51c9524dce04c64677ced32ca49605) |
| **Audit Trail** | Standard auto-increment SQL table | Rogue DBA or insider can silently alter/delete rows | Cryptographic HMAC-SHA256 sequential hash chain with verifier | [`336a6cf`](https://github.com/Chaitanya06-source/TrustVault/commit/336a6cf509aba6aa06db577231b0e622394faa13) |
| **Intrusion Detection**| Silent 403 on authorization failure | Unrecorded probing / blind reconnaissance | Atomically log `ACCESS_DENIED_*` before returning HTTP 403 | [`bc8a758`](https://github.com/Chaitanya06-source/TrustVault/commit/bc8a75897f51c9524dce04c64677ced32ca49605) |
| **Upload Security** | Trust client-provided `file.mimetype` | Disguised executable (.exe with .pdf name) accepted | Binary magic-byte inspection (checking `%PDF`, blocking `MZ`/`ELF`) | [`fe41bbc`](https://github.com/Chaitanya06-source/TrustVault/commit/fe41bbc495c5f757ccbef4c5950f4880ca3ac505) |
| **AI Boundaries** | Autonomous permission expansion | AI hallucination leaks confidential documents | Mandatory human-in-the-loop confirmation with audited decision | [`2b2fb2c`](https://github.com/Chaitanya06-source/TrustVault/commit/2b2fb2c43413e9ffac1f38a6555989a99ddee624) |


### Entry 6: Production Audit Verification Mismatch and Documentation Correction
* **Date**: October 23, 2026
* **Component**: PostgreSQL audit-chain verifier and submission documentation
* **Prompt Summary**:
  > “Help diagnose the production audit verifier reporting a hash mismatch at record 1, without deleting records or changing the secret blindly, and make the submission documents match the actual deployed state.”
* **What the AI Produced / Investigation Result**:
  The deployed endpoint returned `valid: false`, `brokenAt: 1`, and `Audit record hash mismatch` for a chain containing audit records. Source inspection found that the PostgreSQL writer and verifier calculate HMAC-SHA256 over ordered record fields. Some security tests still initialize the older SQLite database and seed path, so their results do not prove that the deployed PostgreSQL path is covered.
* **What Was Wrong or Uncertain (Specifically)**:
  The original documentation described audit tamper detection as verified and could be read as implying that production verification passed. The actual cause of the first-record mismatch is not established. A mismatch alone does not distinguish a secret mismatch, historical serialization differences, stored field representation differences, or malicious modification.
* **What We Did Instead**:
  We did not change the production secret, rewrite hashes, delete records, or claim a passing verifier. We updated the README and threat model to disclose the observed failure, distinguish the sequential HMAC chain from a Merkle tree, and explain the test-coverage limitation. We added a route-level API reference and a five-minute demo script that explicitly instructs the presenter to show the real verifier result.
* **Status**: Documentation corrected; root-cause diagnosis and production verification fix remain unfinished. This entry records the investigation and correction, not a claim that the verifier is fixed.
