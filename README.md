# TrustVault — Zero-Trust Document Sharing & Cryptographic Audit Ledger

> **Platform Mission**: Build a document platform where the wrong person can never read the file, and you can prove who read it.  
> **Core Architecture**: Zero-Trust Permission Gateway • Instant Revocation • Cryptographic Tamper-Evident Hash Chain • Magic-Byte Upload Defense.

---

## 1. Quick Start (From a Clean Clone)

### Prerequisites
- Node.js **v20+** or **v22+** / **v26+** (built using native `node:sqlite` for zero native build dependencies on Windows/Linux/macOS)
- npm v10+

### Installation & Test Execution
```bash
# 1. Clone repository and navigate to workspace
git clone <repository-url>
cd trustvault

# 2. Install dependencies (server and client)
npm install
npm --prefix client install

# 3. Seed database with roles, accounts, and sample confidential documents
npm run seed

# 4. Run automated security test suite (proves isolation, revocation & tamper detection)
npm test

# 5. Run cryptographic audit chain verification CLI
npm run audit:verify

# 6. Start full platform (both backend API and frontend UI)
npm run dev
```

Visit the application in your browser:
* **Frontend Application**: `http://localhost:3000` (or `http://localhost:4000` when running production build)
* **Backend API**: `http://localhost:4000/api`

---

## 2. Seed Credentials for Evaluation

The database is pre-seeded with five test accounts covering all platform roles. The front-end also features a **Fast Persona Switcher** toolbar at the top of the screen to switch identities with a single click.

| Role | Account Name | Email | Password | Intended Test Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | Audit Administrator | `admin@trustvault.internal` | `AdminPassword123!` | Verifies cryptographic audit chain, inspects security alert anomalies (e.g. repeated denied probes by Eve), manages account activations. **Cannot read confidential document bytes without owner grant.** |
| **Document Owner** | Alice (Finance Director) | `alice@trustvault.internal` | `AlicePassword123!` | Uploads financial documents, grants access to Bob, revokes access immediately, deletes owned documents, inspects document audit trail. |
| **Document Owner** | Charlie (HR Director) | `charlie@trustvault.internal` | `CharliePassword123!` | Holds strictly confidential executive salary letters. **Bob and Eve have 0 access to these files.** |
| **Viewer** | Bob (Financial Analyst) | `bob@trustvault.internal` | `BobPassword123!` | Can view metadata and download only documents explicitly granted by Alice. Receives HTTP 403 on ungranted documents. Cannot grant access to others. |
| **Attacker** | Eve (Unauthorized) | `eve@external.org` | `EvePassword123!` | Holds 0 permissions. Attempts to read, download, search, or probe documents return HTTP 403 and are permanently chained into the audit ledger as `ACCESS_DENIED_*`. |

---

## 3. The Three Non-Negotiables: How TrustVault Delivers

### Non-Negotiable #1: A document is reachable only by someone who was granted it. The server decides, every time.
* **Storage Isolation**: Uploaded files are stored under random non-predictable UUIDs in an isolated directory (`storage/files/`) outside the public web root. There are **zero static URLs** and zero direct file paths.
* **Database-Enforced Authorization**: Every document request (`/api/documents/:id`, `/api/documents/:id/download`, etc.) executes a live SQL check against `documents` and `document_permissions`. If no grant exists, the server immediately denies the request.
* **Search Isolation**: The search query itself applies row-level filtering (`(d.owner_id = :userId OR dp.user_id = :userId)`). An unauthorized user cannot even discover that a confidential document exists.
* **Browser Security Headers**: Downloads are streamed with:
  ```http
  Content-Disposition: attachment; filename="sanitized_name"
  X-Content-Type-Options: nosniff
  Content-Security-Policy: default-src 'none'
  Cache-Control: no-store, no-cache, must-revalidate, private
  Pragma: no-cache
  ```

### Non-Negotiable #2: You can prove who reached it. An audit trail that can be quietly altered is not evidence.
* **Cryptographic HMAC-SHA256 Hash Chain**: Each audit record is chained to the previous record's hash, forming an append-only cryptographic ledger:
  $$\text{Hash} = \text{HMAC-SHA256}(\text{SECRET}, \text{sequence} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{target} \parallel \text{status} \parallel \text{prev\_hash})$$
  Block $0$ links to a Genesis Hash ($64$ zeros).
* **Tamper Verification**: The endpoint `GET /api/audit/verify` and CLI script `npm run audit:verify` recalculate all hashes sequentially. If an internal administrator or attacker modifies even a single byte in the database, the chain breaks and the exact corrupted record index is identified.
* **Refused Attempts Recorded**: Every unauthorized attempt (view, download, edit, delete, grant) is committed to the audit ledger as `ACCESS_DENIED_*` before returning HTTP 403.

### Non-Negotiable #3: Taking access away works immediately.
* **Zero Long-Lived Pre-Signed URLs**: Pre-signed cloud storage URLs (e.g. S3 15-minute tokens) create an unacceptable window of vulnerability. TrustVault proxies all bytes through the application server with real-time DB lookups.
* **Instant Revocation Effect**: When an owner calls `DELETE /api/documents/:id/permissions/:userId`, the grant is deleted from `document_permissions`. Any subsequent request from that user—even 1 millisecond later—returns HTTP 403.
* **Automated Proof**: Tested and verified in [`server/tests/immediate_revocation.test.ts`](file:///server/tests/immediate_revocation.test.ts).

---

## 4. Permission Model (In Our Own Words)

TrustVault uses a **Zero-Trust, Owner-Centric Discretionary Access Control (DAC)** model combined with **Strict Role Separation of Duties**:

1. **Document Ownership**: The user who uploads a document is its permanent owner. Only the owner can:
   - Grant 'view' or 'edit' permissions to named users
   - Revoke permissions with immediate effect
   - Update document versions or metadata
   - Delete the document
   - View the document's audit history
2. **Permission Levels per Document**:
   - `view`: Allows reading document metadata and downloading the file stream.
   - `edit`: Allows updating metadata and uploading replacement file versions. Cannot grant access or delete.
   - `none`: User cannot read, download, or discover the document.
3. **The Administrator Boundary (Separation of Duties)**:
   - In many flawed systems, "Admin" is given superuser rights to read all confidential company documents.
   - In TrustVault, **the Administrator cannot read or download confidential document contents unless explicitly granted by the owner**. The Administrator oversees system health, verifies cryptographic audit integrity, and monitors security alert anomalies. This prevents executive salary or client contract leaks via rogue IT administrators.

---

## 5. Where AI Fits (and Where It Must Not Decide)

TrustVault includes an **AI Access Advisor & Sensitivity Classifier**:
* **Advisory Role Only**: When uploading or sharing a document, the AI analyzes the title, category, and context to propose a sensitivity level (Confidential, Restricted, Internal) and least-privilege recipient recommendations.
* **The Non-Negotiable Machine Boundary**: The AI **never widens or applies permissions on its own**.
* **Audited Human Confirmation**: The document owner must review the suggestion in the UI and click "Confirm". Both the generated recommendation (`AI_ADVISORY_SUGGESTION_GENERATED`) and the human decision (`AI_ADVISORY_CONFIRMED`) are permanently chained into the audit ledger.

---

## 6. API Documentation & Access Control Matrix

| Endpoint | Method | Allowed Caller Roles | Minimum Document Permission | Description |
| :--- | :--- | :--- | :--- | :--- |
| `/api/auth/login` | POST | Public | None | Authenticates user; returns JWT token. |
| `/api/auth/me` | GET | Authenticated | None | Returns active user profile. |
| `/api/auth/users` | GET | Authenticated | None | Lists users for permission selection. |
| `/api/documents` | POST | `owner`, `admin` | None | Uploads and validates new document. |
| `/api/documents` | GET | Authenticated | Filtered | Lists documents caller owns or has grants for. |
| `/api/documents/:id` | GET | Authenticated | `view` or `owner` | Retrieves document metadata. |
| `/api/documents/:id/download` | GET | Authenticated | `view` or `owner` | Streams raw file bytes with anti-cache headers. |
| `/api/documents/:id` | PUT | Authenticated | `edit` or `owner` | Updates metadata or uploads replacement version. |
| `/api/documents/:id` | DELETE | Authenticated | `owner` only | Deletes document and cleans up vault storage. |
| `/api/documents/:id/permissions` | GET | Authenticated | `owner` only | Lists active named grants for document. |
| `/api/documents/:id/permissions` | POST | Authenticated | `owner` only | Grants 'view' or 'edit' to named user. |
| `/api/documents/:id/permissions/:userId` | DELETE | Authenticated | `owner` only | Revokes permission with immediate effect. |
| `/api/audit` | GET | `admin`, `owner` | Filtered | Admin sees system-wide; Owner sees their docs. |
| `/api/audit/verify` | GET | `admin`, `owner` | None | Recalculates and verifies cryptographic hash chain. |
| `/api/admin/alerts` | GET | `admin` only | None | Security anomaly alert feed (denied probes). |
| `/api/admin/metrics` | GET | `admin` only | None | Document count, storage size, and audit telemetry. |
| `/api/admin/users/:id/toggle` | POST | `admin` only | None | Deactivates/activates user account immediately. |
| `/api/ai/recommend` | POST | Authenticated | None | Proposes least-privilege access policy. |
| `/api/ai/confirm` | POST | Authenticated | `owner` only | Applies human-confirmed AI recommendations. |

---

## 7. Automated Test Suite (Proving Security Invariants)

Run the full suite with:
```bash
npm test
```

### The 24 Automated Security Tests:
1. **Document Security Isolation** ([`security_isolation.test.ts`](file:///server/tests/security_isolation.test.ts)):
   - Proves ungranted user cannot view metadata (403 Forbidden).
   - Proves ungranted user cannot download bytes (403 Forbidden).
   - Proves search queries do not leak existence of private documents.
   - Proves ungranted user cannot edit or delete another user's document.
   - Proves viewer cannot grant access to third parties.
   - Proves unauthenticated requests are universally rejected (401).
2. **Immediate Revocation** ([`immediate_revocation.test.ts`](file:///server/tests/immediate_revocation.test.ts)):
   - Verifies owner can grant access -> viewer downloads file -> owner revokes -> viewer download immediately fails with 403 with zero delay.
3. **Tamper-Evident Audit Ledger** ([`audit_trail_tamper_detection.test.ts`](file:///server/tests/audit_trail_tamper_detection.test.ts)):
   - Verifies refused access attempts are recorded as `DENIED`.
   - Proves direct SQL alteration of an audit record causes cryptographic verification failure and pinpoints the exact corrupted block.
   - Proves row deletion causes sequence continuity failure.
4. **Upload Validation & Malware Defense** ([`upload_validation.test.ts`](file:///server/tests/upload_validation.test.ts)):
   - Blocks disguised Windows PE executables (`MZ` header) masked as `.pdf`.
   - Blocks disallowed file extensions (`.exe`, `.sh`).
   - Sanitizes directory traversal filenames (`../../etc/passwd`).
5. **AI Advisory Safety** ([`ai_access_advisor.test.ts`](file:///server/tests/ai_access_advisor.test.ts)):
   - Proves AI recommendations do not widen access without explicit human confirmation.
6. **Authorization Check Sensitivity Proof** ([`auth_check_removal_demonstration.test.ts`](file:///server/tests/auth_check_removal_demonstration.test.ts)):
   - Proves that removing the authorization check causes the security tests to fail.

---

## 8. What We Deliberately Chose Not to Build (and Why)

1. **Folder-Based Nested Permission Inheritance**:
   * *Why Left Out*: Folder inheritance is the #1 cause of catastrophic data leakage in enterprise document systems ("Someone is given access to a folder so they can see one file, and they can now see forty"). TrustVault uses explicit per-document grants.
2. **Pre-Signed Cloud Storage Download URLs**:
   * *Why Left Out*: Pre-signed S3 tokens cannot be revoked instantly without complex IAM rewriting. All file streams pass through the application server with real-time permission evaluation.
3. **Public Unauthenticated Sharing Links**:
   * *Why Left Out*: Secret link sharing ("anyone with the link can view") destroys auditability because the server cannot prove who actually opened the file. TrustVault requires named user authentication for every read.
4. **Client-Side DRM / Screen Watermarking**:
   * *Why Left Out*: Browser-based canvas overlays and DOM watermarking provide false security and can be bypassed in DevTools or via mobile phone cameras (the "Analogue Hole"). We prioritized cryptographically provable server-side non-repudiation.

---

## 9. Deliverables Reference

* [`THREATS.md`](file:///THREATS.md) — 15+ threat vectors modeled, mitigated, and verified.
* [`PROMPTS.md`](file:///PROMPTS.md) — 5 dated AI interaction entries documenting flawed code and security fixes.
* [`server/src/services/auditService.ts`](file:///server/src/services/auditService.ts) — HMAC-SHA256 cryptographic hash chain engine.
* [`server/src/services/permissionService.ts`](file:///server/src/services/permissionService.ts) — Real-time zero-trust authorization and immediate revocation logic.
* [`server/tests/`](file:///server/tests/) — Complete automated penetration and regression test suite.
