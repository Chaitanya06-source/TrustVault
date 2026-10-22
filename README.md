# TrustVault — Zero-Trust Document Sharing & Cryptographic Audit Ledger

> **Platform mission:** Ensure documents are accessible only to authorized users and maintain a tamper-evident record of security-relevant activity.
>
> **Core principles:** Zero-trust authorization · Least privilege · Immediate access revocation · Cryptographic audit integrity · Secure file validation

TrustVault is a secure document-sharing platform built around server-side authorization, explicit document permissions, protected file storage, and a cryptographically verifiable audit ledger. It also includes an AI-assisted access advisor that supports human decisions without independently granting permissions.

**Live application:** [Open TrustVault](https://trustvault-frontend-3scb.onrender.com)  
**Backend health check:** [Check API health](https://trustvault-1ndr.onrender.com/api/health)  
**Source code:** [GitHub repository](https://github.com/Chaitanya06-source/TrustVault)

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [AI Access Advisor](#ai-access-advisor)
- [Technology Stack](#technology-stack)
- [Live Deployment](#live-deployment)
- [Local Development Setup](#local-development-setup)
- [Testing](#testing)
- [API Reference](#api-reference)
- [Design Decisions](#design-decisions)
- [Project Documentation](#project-documentation)

## Features

- **Zero-trust document authorization:** Validate permissions on protected document operations instead of trusting the client.
- **Granular access control:** Document owners can grant or revoke `view` and `edit` permissions for named users.
- **Immediate revocation:** Subsequent requests are checked against current permissions.
- **Protected document storage:** Store files in Supabase Storage and access them through the backend.
- **Tamper-evident audit ledger:** Use an HMAC-SHA256 hash chain to detect unauthorized changes to audit records.
- **Security monitoring:** Record denied access attempts and provide administrative audit and alert views.
- **Upload validation:** Validate file types, extensions, and filenames to reduce common upload risks.
- **AI-assisted access recommendations:** Suggest document sensitivity and least-privilege sharing options while leaving permission decisions to the user.
- **Role separation:** Separate administrative responsibilities from document ownership and content access.

## Architecture

TrustVault uses a frontend, backend API, PostgreSQL database, and object-storage service.

```text
User / Browser
      |
      v
Frontend Application
      |
      v
Backend API (Node.js + TypeScript)
      |
      +---- Authentication and authorization
      |
      +---- Document and permission services
      |
      +---- Cryptographic audit services
      |
      +---- AI advisory services
      |
      +---- PostgreSQL (Neon)
      |
      +---- Supabase Storage
```

### Core components

| Component | Responsibility |
|---|---|
| Frontend | User interface for authentication, document management, permissions, and audit information |
| Backend API | Validates requests and enforces authorization rules |
| PostgreSQL | Stores users, documents, permissions, and audit records |
| Supabase Storage | Stores uploaded document objects |
| Audit service | Maintains and verifies the cryptographic audit chain |
| AI advisory service | Generates access and sensitivity recommendations for human review |

The backend is the security boundary. The frontend does not replace server-side authorization checks.

## Security Model

### 1. Server-side authorization

Every protected operation must be authorized by the backend. A user should not gain access merely by knowing a document ID or modifying a client request.

- Document access is governed by ownership and explicit permissions.
- Document listings and search must filter results according to the requesting user's access.
- Unauthorized requests are denied.
- File downloads are handled through the application rather than by exposing public document paths.

### 2. Document permissions

TrustVault follows an owner-centric discretionary access control model.

| Permission | Capabilities |
|---|---|
| `owner` | Manage the document, grant or revoke access, update supported document information, and inspect its audit history |
| `view` | Read permitted document metadata and download its contents |
| `edit` | Perform supported document editing operations without automatically receiving ownership privileges |
| `none` | No document access |

The administrator role does not automatically grant permission to read every confidential document. Administrative capabilities and document-content permissions are separate concerns.

### 3. Immediate revocation

When a document owner revokes a user's permission, subsequent protected requests must be checked against the updated permission state.

TrustVault avoids relying on long-lived, pre-signed download links as its document authorization mechanism. The application backend mediates access to stored document contents.

### 4. Cryptographic audit integrity

TrustVault uses an HMAC-SHA256 hash chain to make unauthorized modifications to audit records detectable.

Conceptually, each record incorporates its contents and the previous record's hash:

```text
current_hash = HMAC-SHA256(
    audit_secret,
    canonical_record_data + previous_hash
)
```

The exact serialization and field ordering must match the implementation.

The audit verification command is:

```bash
npm run audit:verify
```

The verification endpoint is:

```http
GET /api/audit/verify
```

A successful verification indicates that the checked records are consistent with the chain and verification key. It does not, by itself, prove that every possible event was logged or that the signing secret has never been compromised.

**Important:** Keep the audit secret private and separate from public source code. Protect access to the database and signing secret independently.

### 5. Upload validation and response protection

TrustVault includes upload validation and security-oriented download response headers. Depending on the operation, these protections can include:

- Filename sanitization
- File-extension and file-signature checks
- Rejection of disallowed file types
- `X-Content-Type-Options: nosniff`
- Appropriate cache-control headers for confidential content
- Controlled download responses

File validation reduces risk but should not be treated as a guarantee that every uploaded file is harmless.

## AI Access Advisor

TrustVault includes an AI-assisted access advisor and document sensitivity classifier.

The intended workflow is:

1. Analyze document information and context.
2. Suggest a sensitivity category and possible least-privilege recipients.
3. Present the recommendation to the document owner.
4. Require an explicit human decision before applying supported recommendations.
5. Record relevant advisory and confirmation events in the audit ledger.

The AI component is advisory. It should not independently grant permissions or override the authorization system.

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Node.js, TypeScript, Express |
| Database | PostgreSQL |
| Database hosting | Neon |
| Object storage | Supabase Storage |
| Testing | Vitest |
| Build tooling | TypeScript compiler, Vite |
| Frontend/backend hosting | Render |
| Audit integrity | HMAC-SHA256 |

## Live Deployment

The deployed application is available at:

- **Frontend:** https://trustvault-frontend-3scb.onrender.com
- **Backend health endpoint:** https://trustvault-1ndr.onrender.com/api/health

The frontend uses the production API base URL configured through the `VITE_API_URL` environment variable.

The deployed system relies on PostgreSQL and Supabase Storage. Production credentials and secrets must be configured through the relevant hosting environment, not committed to the repository.

Free hosting services may take time to wake up after inactivity.

## Local Development Setup

### Prerequisites

- Node.js 20 or later
- npm
- Git
- Access to a configured PostgreSQL database
- A configured Supabase project and Storage bucket

### 1. Clone the repository

```bash
git clone https://github.com/Chaitanya06-source/TrustVault.git
cd TrustVault
```

### 2. Install dependencies

```bash
npm install
npm --prefix client install
```

### 3. Configure environment variables

Create a local `.env` file based on the environment configuration required by the project.

The application requires a PostgreSQL connection and Supabase Storage configuration. Set all other required application secrets and settings according to the project's configuration files.

Typical storage and database settings include:

```dotenv
DATABASE_URL=your_postgresql_connection_string
SUPABASE_URL=your_supabase_project_url
SUPABASE_SECRET_KEY=your_supabase_secret_key
SUPABASE_STORAGE_BUCKET=trustvault-documents
```

These are **placeholders, not working credentials**. Replace them locally with your own values. Check the project configuration for any additional required variables.

- Never commit `.env` to GitHub.
- Never paste production secrets into public issues or documentation.
- Use separate development credentials and secrets.
- Do not use example values as production secrets.

### 4. Prepare the database

After configuring the environment, run the project's seed command if the database is ready for initialization:

```bash
npm run seed
```

Only seed a database you intend to initialize with the project's development or evaluation data. Do not run a development seed against a production database without understanding its effects.

### 5. Run the automated tests

For the current local test setup, load environment variables from `.env` explicitly:

```bash
node --env-file=.env node_modules/vitest/vitest.mjs run
```

The test suite requires the relevant environment variables to be available. Keep credentials private and do not include `.env` in commits.

### 6. Verify the audit chain

```bash
npm run audit:verify
```

### 7. Start the application

```bash
npm run dev
```

Open the frontend using the development URL printed by Vite in the terminal. The backend API runs on its configured port, currently `4000` in the local setup.

## Testing

TrustVault uses automated tests to check security behavior and application correctness.

The latest recorded local verification for this project passed **36 tests across 10 test files**. Test results can change as the codebase evolves; run the commands above to verify the current checkout.

Important test areas include:

| Test area | What it checks |
|---|---|
| Document security isolation | Unauthorized users cannot access protected documents |
| Immediate revocation | Revoked access is rejected on subsequent requests |
| Audit tamper detection | Changes to chained audit records are detected |
| Upload validation | Disallowed file types and unsafe filenames are rejected |
| AI advisory safety | AI recommendations do not independently grant permissions |
| Authorization regression | Tests detect failures when required access checks are removed |

Test files are located in [`server/tests/`](server/tests/).

## API Reference

The following table summarizes the documented API surface. Actual access depends on the implemented authorization rules and request validation.

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/auth/login` | POST | Authenticate a user |
| `/api/auth/me` | GET | Retrieve the authenticated user's profile |
| `/api/auth/users` | GET | Retrieve users for permission selection |
| `/api/documents` | GET | List documents visible to the caller |
| `/api/documents` | POST | Upload a document |
| `/api/documents/:id` | GET | Retrieve document metadata |
| `/api/documents/:id` | PUT | Update supported document information |
| `/api/documents/:id` | DELETE | Delete an owned document |
| `/api/documents/:id/download` | GET | Download an authorized document |
| `/api/documents/:id/permissions` | GET | List document permissions |
| `/api/documents/:id/permissions` | POST | Grant document permissions |
| `/api/documents/:id/permissions/:userId` | DELETE | Revoke a user's document permission |
| `/api/audit` | GET | Retrieve authorized audit records |
| `/api/audit/verify` | GET | Verify audit-chain integrity |
| `/api/admin/alerts` | GET | Retrieve administrative security alerts |
| `/api/admin/metrics` | GET | Retrieve administrative metrics |
| `/api/admin/users/:id/toggle` | POST | Activate or deactivate a user |
| `/api/ai/recommend` | POST | Generate AI access recommendations |
| `/api/ai/confirm` | POST | Process a human-confirmed recommendation |

All protected endpoints must be accessed using the authentication and request formats expected by the backend.

## Design Decisions

### Explicit document permissions instead of inherited folder access

Explicit grants make it easier to reason about which users can access individual documents and reduce accidental permission inheritance.

### Backend-mediated downloads instead of public sharing links

Public unauthenticated links make identity verification and reliable access control more difficult. TrustVault is designed around authenticated, permission-checked access.

### Immediate revocation instead of long-lived download tokens

The backend can check the current permission state when a download is requested. Previously downloaded copies cannot, however, be remotely erased from a recipient's device.

### Human approval instead of autonomous AI permission changes

AI can help users evaluate sensitivity and sharing decisions, but permission changes remain subject to application authorization and explicit human confirmation.

### Auditability instead of relying only on application logs

A cryptographic hash chain makes unauthorized changes to linked audit records detectable when verification is performed with the correct secret. It complements, rather than replaces, database protection, secret management, and operational monitoring.

## Project Documentation

- [Threat model](THREATS.md) — Documented security threats and mitigations.
- [AI interaction notes](PROMPTS.md) — Project-related AI interaction and development notes.
- [Backend source code](server/src/)
- [Automated tests](server/tests/)

---

## Security and Responsible Use

TrustVault is a security-focused software project. Its protections should be validated in the target deployment before it is used for sensitive or regulated information.

Security depends on correct configuration, secure secret handling, database and storage permissions, reliable authorization checks, and appropriate operational monitoring.

**Never upload real confidential documents to an unverified development environment.**
