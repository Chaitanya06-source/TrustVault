# TrustVault Threat Model & STRIDE Security Analysis (THREATS.md)

> **Document Status**: Challenge threat model; includes unresolved production verification gaps  
> **Classification**: Internal Security Specification  
> **Architectural Paradigm**: Zero-Trust, Server-Authoritative, Cryptographically Tamper-Evident  

---

## 1. Executive Security Philosophy

TrustVault is engineered under the principle that **access control is a security invariant, not an application feature**. A document platform that leaks even a single unauthorized byte is completely compromised. 

### Scope and evidence standard

This document distinguishes design intent from verified behaviour. A test name in the matrix is not proof that the deployed PostgreSQL implementation was exercised. The deployed audit verifier has returned a mismatch at sequence 1; production audit integrity is currently **not verified**.

### Core Non-Negotiable Axioms
1. **The Server Decides, Every Time**: Access is evaluated at the database layer at the millisecond of byte transfer. UI hiding, client-side routing, and ephemeral pre-signed tokens are rejected as architectural antipatterns.
2. **Cryptographic Proof of Access & Denial**: It must be provable *afterwards* from the ledger who accessed a file, and who attempted to access it and was refused. An audit record that can be modified or deleted without detection is not evidence.
3. **Instant Revocation with Zero Vulnerability Window**: When access is revoked, any subsequent request from that user—even milliseconds later—must fail immediately.

---

## 2. Threat Matrix: Identified Attack Vectors, Mitigations & Verification

| Threat ID | Threat Name | STRIDE Class | Severity | Mitigation Architecture | Verified By Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | Insecure Direct Object Reference (IDOR) on Metadata & Downloads | Elevation of Privilege / Info Disclosure | **CRITICAL** | Real-time SQL JOIN against `document_permissions` table; unpredictable UUIDs; direct download endpoint validation. | `server/tests/security_isolation.test.ts` |
| **THREAT-02** | Pre-Signed S3 URL & Caching Bypass on Revocation | Elevation of Privilege / Repudiation | **CRITICAL** | Zero pre-signed URLs. Streaming proxy via application server; `Cache-Control: no-store` headers; real-time DB check. | `server/tests/immediate_revocation.test.ts` |
| **THREAT-03** | Silent Alteration / Deletion of Audit Trail (Rogue DBA / Insider) | Tampering / Repudiation | **CRITICAL** | HMAC-SHA256 sequential hash chain (not a Merkle tree). A change to covered fields should cause verification to fail when the correct key and canonical serialization are used. Production verification is currently failing at record 1; the root cause is unresolved. | `server/tests/audit_trail_tamper_detection.test.ts` |
| **THREAT-04** | Unrecorded Refusal Attempts (Silent Reconnaissance) | Repudiation / Info Disclosure | **HIGH** | `ACCESS_DENIED_VIEW` and `ACCESS_DENIED_DOWNLOAD` events are chained into the audit ledger before returning 403. | `server/tests/audit_trail_tamper_detection.test.ts` |
| **THREAT-05** | Multipart Path Traversal (`../../etc/passwd`) | Tampering / Elevation of Privilege | **HIGH** | Filename sanitization stripping paths and control bytes. Files stored strictly by UUID in an isolated vault directory. | `server/tests/upload_validation.test.ts` |
| **THREAT-06** | MIME Confusion & Disguised Executable Uploads | Tampering / Elevation of Privilege | **HIGH** | Deep magic byte verification (reads first 512 bytes) verifying headers (`%PDF`, `PK\x03\x04`, `PNG`) and blocking `MZ`/`ELF`. | `server/tests/upload_validation.test.ts` |
| **THREAT-07** | Cross-Site Scripting (XSS) via Browser Inline Execution | Tampering / Info Disclosure | **HIGH** | `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'none'`. | `server/tests/security_isolation.test.ts` |
| **THREAT-08** | Autonomous AI Permission Widening & Hallucination | Elevation of Privilege | **HIGH** | AI is strictly an advisory assistant. Machine can never execute grants on its own. Explicit human confirmation is required and audited. | `server/tests/ai_access_advisor.test.ts` |
| **THREAT-09** | Horizontal Privilege Escalation in Permission Grants | Elevation of Privilege | **HIGH** | Only the document owner (`d.owner_id === requester.id`) can grant or revoke permissions. Non-owners receive 403. | `server/tests/security_isolation.test.ts` |
| **THREAT-10** | Timing Attacks on Password & Key Verification | Info Disclosure | **MEDIUM** | Uses `crypto.scryptSync` with `crypto.timingSafeEqual` and computed dummy hashes for non-existent users. | `server/tests/security_isolation.test.ts` |
| **THREAT-11** | Information Leakage via Search Queries & Title Enumeration | Info Disclosure | **HIGH** | Database queries enforce row-level security (`(d.owner_id = ? OR dp.user_id = ?)`). Unpermitted titles never appear in search. | `server/tests/security_isolation.test.ts` |
| **THREAT-12** | Mass Denial of Service via Huge Multipart Buffers | Denial of Service | **MEDIUM** | Multer buffer limit strictly capped at 25MB (`LIMIT_FILE_SIZE`). Excess payload terminated at socket header read. | `server/tests/upload_validation.test.ts` |
| **THREAT-13** | Immediate User Account Deactivation Bypass (Stale JWTs) | Elevation of Privilege | **HIGH** | `authenticate` middleware re-checks `users.is_active === 1` on every request. Deactivation revokes all active tokens immediately. | `server/tests/security_isolation.test.ts` |
| **THREAT-14** | TOCTOU (Time-of-Check to Time-of-Use) Streaming Race | Tampering / Info Disclosure | **HIGH** | Permission validation and stream descriptor acquisition occur within a single synchronous controller block. | `server/tests/immediate_revocation.test.ts` |
| **THREAT-15** | Accidental Authorization Check Removal | Elevation of Privilege | **CRITICAL** | Automated test suite fails catastrophically if any permission middleware or check is removed or short-circuited. | `server/tests/auth_check_removal_demonstration.test.ts` |

---

## 3. Deep Dive into Critical Threat Vectors

### Threat 01: Insecure Direct Object Reference (IDOR)
* **Attack Scenario**: Attacker authenticates as viewer Eve. Eve inspects network traffic, obtains a confidential document UUID (`f47ac10b-58cc-4372-a567-0e02b2c3d479`), and calls `GET /api/documents/f47ac10b-58cc-4372-a567-0e02b2c3d479/download`.
* **Vulnerable Architecture**: A system that looks up the document by ID without joining the user's explicit permission grants, or a system that relies on front-end button hiding.
* **TrustVault Defense**:
  ```sql
  SELECT d.*, dp.permission_level 
  FROM documents d 
  LEFT JOIN document_permissions dp ON d.id = dp.document_id AND dp.user_id = :userId 
  WHERE d.id = :docId AND (d.owner_id = :userId OR dp.permission_level IS NOT NULL)
  ```
  If this query returns null, `PermissionService.checkAccess` flags an immediate refusal, logs `ACCESS_DENIED_DOWNLOAD` into the hash chain, and terminates with HTTP 403.
* **Test Proof**: [`security_isolation.test.ts`](file:///server/tests/security_isolation.test.ts) proves that Eve receives HTTP 403 and zero document bytes.

---

### Threat 02: Pre-Signed URL & Caching Bypass on Revocation
* **Attack Scenario**: Alice grants Bob access to an M&A contract. At 14:00, Bob generates a download link. At 14:05, Alice revokes Bob's access. At 14:10, Bob uses the previously issued link or browser cache to download the file.
* **Why Pre-Signed URLs Fail**: In AWS S3 or Google Cloud Storage, pre-signed URLs are cryptographically self-contained tokens valid until `Expires` (typically 15 to 60 minutes). Revoking user permissions in an application database does *not* invalidate an in-flight S3 signature unless complex IAM bucket policies are dynamically rewritten.
* **TrustVault Defense**:
  1. All file byte streams are proxied through the server (`GET /api/documents/:id/download`).
  2. Every single download request re-queries the database for active permissions.
  3. Strict anti-caching HTTP headers are enforced:
     - `Cache-Control: no-store, no-cache, must-revalidate, private`
     - `Pragma: no-cache`
     - `Expires: 0`
* **Test Proof**: [`immediate_revocation.test.ts`](file:///server/tests/immediate_revocation.test.ts) proves that the instant `DELETE /api/documents/:id/permissions/:userId` completes, the very next request from that user returns HTTP 403.

---

### Threat 03: Rogue DBA or Insider Tampering with Audit History
* **Attack Scenario**: An internal rogue administrator accesses the underlying database and updates an audit record to conceal that they downloaded executive salary letters, changing `actor_email = 'admin@internal'` to `actor_email = 'innocent@internal'`.
* **Vulnerable Architecture**: Standard SQL tables with no cryptographic binding or append-only guarantees.
* **TrustVault Defense**:
  - Each audit record is cryptographically bound into an unbroken HMAC-SHA256 hash chain:
    $$\text{Payload} = \text{sequence\_number} \parallel \text{timestamp} \parallel \text{actor\_id} \parallel \text{action} \parallel \text{target\_id} \parallel \text{status} \parallel \text{prev\_hash}$$
    $$\text{Record Hash} = \text{HMAC-SHA256}(\text{SECRET\_SALT}, \text{Payload})$$
  - The first record links to a Genesis Hash ($64$ zeros).
  - An automated verification routine [`AuditService.verifyChainIntegrity()`](file:///server/src/services/auditService.ts) recalculates the chain from Genesis to head. If any row is edited, deleted, or reordered, the chain fails and flags the exact corrupted block index.
* **Test Proof**: [`audit_trail_tamper_detection.test.ts`](file:///server/tests/audit_trail_tamper_detection.test.ts) simulates direct SQL modification of an audit record and asserts that the verifier detects the tampering and reports `valid: false`.

---

### Threat 04: Unrecorded Refusal Attempts (Blind Reconnaissance)
* **Attack Scenario**: Attacker runs a script attempting to enumerate document endpoints. If the system only logs *successful* requests, the security team has zero evidence that a brute force or scanning attack occurred.
* **TrustVault Defense**:
  - Every authorization check is wrapped in an audit recorder.
  - When a request is denied, an `ACCESS_DENIED_VIEW` or `ACCESS_DENIED_DOWNLOAD` record is committed to the hash chain *before* the 403 Forbidden response is sent.
  - Security Telemetry in the Admin Dashboard automatically flags actors who trigger $\ge 2$ denied attempts.

---

### Threat 06: MIME Confusion & Executable Masking
* **Attack Scenario**: Attacker takes a Windows PE executable (`.exe`) or shell script and renames it to `financial_audit.pdf`. When downloaded by an employee, the file triggers malicious execution.
* **TrustVault Defense**:
  - Validates file extension against a strict whitelist.
  - Inspects magic bytes (first 512 bytes):
    - PDF must begin with `%PDF`
    - PNG must begin with `\x89PNG\r\n\x1a\n`
    - OpenXML (.docx, .xlsx) must begin with ZIP header `PK\x03\x04`
    - Plain text/CSV/JSON must be valid UTF-8 and contain no binary null bytes
  - Any file containing PE `MZ` or ELF `\x7fELF` binary headers is unconditionally rejected.
* **Test Proof**: [`upload_validation.test.ts`](file:///server/tests/upload_validation.test.ts) tests uploading a PE header disguised as a PDF and asserts rejection with HTTP 400.

---

### Threat 08: Autonomous AI Access Escalation
* **Attack Scenario**: An AI agent integrated into the platform misinterprets a document summary or hallucinates an organizational rule, autonomously granting permission to all company employees.
* **TrustVault Defense**:
  - The AI Access Advisor is strictly decoupled from the permission execution engine.
  - The AI can only return an *advisory recommendation* with a sensitivity classification and rationale.
  - The human owner must explicitly inspect the suggestion and click "Confirm".
  - Both the AI advisory generation (`AI_ADVISORY_SUGGESTION_GENERATED`) and the human owner's decision (`AI_ADVISORY_CONFIRMED` / `AI_ADVISORY_REJECTED`) are recorded into the tamper-evident audit ledger.
* **Test Proof**: [`ai_access_advisor.test.ts`](file:///server/tests/ai_access_advisor.test.ts) proves that AI recommendations do not modify the database until explicit human confirmation.

---

## 4. Knowingly Accepted Risks & Design Trade-offs

Security engineering requires transparently documenting what was intentionally not built, and why:

### 1. Physical Database File Destruction (Root OS Wipe)
* **Accepted Risk**: If an attacker gains root operating system access (`SYSTEM` / `root`) and executes `rm -rf data/trustvault.db` or drops the physical disk, the audit database is destroyed.
* **Why Accepted**: Hardware-level write-once-read-many (WORM) storage or hardware security modules (HSM) require dedicated enterprise appliances.
* **Production Recommendation**: Replicate the latest audit hash head to an external public blockchain or append-only AWS CloudWatch log stream every 60 seconds.

### 2. Client-Side Screen Capture / The "Analogue Hole"
* **Accepted Risk**: Once an authorized user legitimately downloads or displays a confidential PDF on their monitor, they can take a screenshot or photograph the screen with a mobile phone.
* **Why Accepted**: Software running in a standard web browser cannot prevent physical cameras or hardware screen capture cards without intrusive proprietary kernel drivers.
* **Mitigation Included**: TrustVault embeds personalized audit trails so that if a document leaks, the company can immediately verify who had authorized access and when they downloaded it.

### 3. File Level Encryption-At-Rest via File System vs Application Key Wrapping
* **Accepted Risk**: File bytes on disk are stored with UUID names outside the web root. In this challenge release, disk-level BitLocker/dm-crypt protects the physical volume rather than per-document envelope encryption with KMS keys.
* **Why Accepted**: In a single-server deployment without a managed KMS (e.g., AWS KMS or HashiCorp Vault), storing symmetric keys in the application process memory provides negligible additional security against a full process dump while significantly increasing streaming latency.

---

## 5. Known Verification Gaps (2026-10-23)

The deployed `GET /api/audit/verify` endpoint has returned `valid: false`, `brokenAt: 1`, with `Audit record hash mismatch`. This must be treated as an unresolved verification failure, not as proof of malicious tampering and not as a successful integrity check. Potential causes include a key mismatch, differences between stored field representations and the values used to calculate the hash, or historical records written under a different implementation. These are hypotheses, not established causes.

Do not rotate the production HMAC secret, rewrite hashes, delete records, or reseed the database as a shortcut: such actions can make the evidence harder to diagnose and may invalidate existing records. The next engineering step is a controlled read-only comparison of the first stored record's fields, the configured secret identity (never its value), and the exact serialization used by both writer and verifier. Once diagnosed, test the fix against a disposable database and verify the production chain without mutating its history.

The existing security test files referenced in this threat model include tests that initialize the legacy SQLite harness. Their passing results do not, by themselves, prove that the deployed PostgreSQL implementation is covered by the same tests. Treat each mitigation as locally tested only where the relevant test actually exercises the implementation under discussion.

## 6. Verification Checklist for Evaluators

When evaluating TrustVault, execute the automated security verification suite:
```bash
npm test
```
Run the current test suite and inspect the result. Historical counts are not a guarantee for the current branch. Confirm that tests exercise the PostgreSQL services used in deployment; SQLite-based tests alone do not establish production-path coverage. Verify the deployed audit endpoint separately and record its actual result.

## 7. Additional Threats and Explicitly Unresolved Risks

The following risks are not marked as mitigated merely because they are documented. They require engineering work and/or environment-specific tests before a mitigation can be claimed.

| ID | Risk | Current state | Impact | Next action |
|---|---|---|---|---|
| THREAT-16 | Audit-tail truncation | A local hash chain does not prove that its newest rows still exist. Removing a suffix can leave a valid prefix. | Privileged DB access could hide recent events. | Anchor sequence number and head hash in an independently administered append-only system and compare it during verification. |
| THREAT-17 | HMAC secret in application environment | Accepted limitation: a server/process compromise that exposes the secret may let an attacker recompute hashes. | Chain authenticity is not independent of the application host. | Use managed secret storage/KMS with restricted access and documented key rotation. |
| THREAT-18 | Login brute force | No rate limiting or lockout is confirmed in the inspected login route. | Password guessing and resource exhaustion. | Add IP/account-based rate limits, progressive delays, monitoring and tests. |
| THREAT-19 | JWT theft, XSS and logout | JWT lifetime is eight hours. Frontend storage and logout invalidation need verification; stateless tokens do not become invalid merely because the UI logs out. | A stolen token may be replayed until expiry or account deactivation. | Prefer HttpOnly/Secure/SameSite cookies or short-lived tokens with server-side revocation/refresh rotation; test logout and XSS assumptions. |
| THREAT-20 | CORS origin reflection | Current app configuration uses origin: true with credentials rather than a strict allowlist. CORS is not authorization, but broad reflection increases browser-based exposure. | Unintended browser origins may be permitted. | Allow only the deployed frontend and required development origins; test allowed and rejected origins. |
| THREAT-21 | Document existence oracle | Some handlers may distinguish missing documents (404) from existing-but-forbidden documents (403). | Authenticated attackers may infer document ID existence. | Use consistent responses for missing and unauthorized documents where appropriate; test status/body/timing. |
| THREAT-22 | ZIP-based Office validation | .docx/.xlsx validation checks ZIP signature, not full package structure or decompressed size. | ZIP bombs, malformed packages or macro-enabled files renamed to allowed extensions may bypass policy or consume resources. | Validate package parts, reject macro-enabled types, limit entries and uncompressed size, and scan when available. |
| THREAT-23 | Revocation during an active download | Authorization is checked at request time. Bytes already sent cannot be recalled, and a request that passed the check may finish after revocation. | An in-progress transfer may complete after revocation. | Define revocation as blocking subsequent requests; if stronger semantics are required, implement cancellation-aware streaming and test concurrent revocation. |
| THREAT-24 | Ephemeral deployment filesystem | Current file service uses local storage/files; durable object storage or a persistent Render disk is not established by the inspected source. | File bytes may disappear on restart/redeploy while DB metadata remains. | Configure persistent storage or implement private object storage and test upload/download after redeploy. |
| THREAT-25 | Legacy tests versus deployed PostgreSQL | Some tests use legacyTestApp and SQLite rather than production PostgreSQL services. | Passing tests may miss regressions in the deployed path. | Add disposable-PostgreSQL integration tests for IDOR, revocation, permissions, denied logging and audit verification. |
| THREAT-26 | Recipient directory enumeration | On this branch, GET /api/auth/users is restricted to owner/admin and has a new route-level regression test; the test still needs to be run. | Previously any authenticated viewer could enumerate recipient emails. | Run the test and confirm viewers get 403 and the service is not called. |

## 8. Verification Status — Do Not Overclaim

- Observed in investigation notes: the deployed audit verifier returned `valid: false`, `brokenAt: 1`, and `Audit record hash mismatch`.
- Not established: the root cause, whether the configured secret matches every historical row, or whether the database was tampered with.
- Not established: persistence of uploaded file bytes across Render restarts/redeploys.
- Not established: whether tests detect removal of the production PostgreSQL download authorization check. The existing test named `auth_check_removal_demonstration.test.ts` uses the legacy SQLite harness and directly replaces a service method; it is not a reliable mutation test of the deployed route.
- Implemented on this branch but not yet executed here: a role restriction on `GET /api/auth/users` and a route-level regression test.

These statements are intentionally conservative. Change an item to verified only after recording the exact test/command and its actual result.