# TrustVault API and Authorization Reference

This reference describes the current PostgreSQL route wiring on the fix/submission-readiness branch. It is not a substitute for endpoint-level integration tests. All endpoints use JSON unless marked as multipart.

## Authentication

Send Authorization: Bearer <JWT> for protected endpoints. Tokens currently expire after eight hours. The middleware re-reads the user record and rejects missing/deactivated users. Do not place tokens in URLs: query-string token support in middleware can expose tokens through logs, browser history and referrers; remove it before production use.

Roles: admin, owner, and viewer. Admin privileges do not automatically grant document-content access.

## Routes

| Method and path | Access expected/current route policy | Purpose / notes |
|---|---|---|
| GET /api/health | Public | Service health check; does not prove database integrity. |
| POST /api/auth/login | Public | Email/password login. Rate limiting is not implemented in the inspected route. |
| GET /api/auth/me | Any authenticated active user | Current user's profile. |
| GET /api/auth/users | Owner/admin on this branch | Named recipient directory. A new route-level regression test was added; run it before deployment. |
| GET /api/documents | Any authenticated user; results must be filtered by ownership/grants | Search/list accessible documents. Supports query/category/owner/date filters in route code. |
| POST /api/documents | Owner/admin by route middleware | Multipart upload with file and metadata. |
| GET /api/documents/:id | Authenticated; service must authorize owner/grant | Read metadata for an accessible document. |
| GET /api/documents/:id/download | Authenticated; service must authorize owner/grant on each request | Download protected bytes. Never expose local storage paths. |
| PUT /api/documents/:id | Authenticated; service must enforce owner/edit permission | Update metadata or replacement file, subject to service authorization. |
| DELETE /api/documents/:id | Authenticated; service must enforce ownership | Delete an owned document. |
| GET /api/documents/:id/permissions | Authenticated; permission service must restrict to owner | List named grants for a document. |
| POST /api/documents/:id/permissions | Authenticated; permission service must restrict to owner | Grant view or edit to a named user. |
| DELETE /api/documents/:id/permissions/:userId | Authenticated; permission service must restrict to owner | Revoke a named user's grant. Subsequent requests should be denied; already transmitted bytes cannot be recalled. |
| GET /api/audit | Admin; owner only for their own document with documentId; viewer denied | Retrieve audit records. Owners must specify a document ID. |
| GET /api/audit/verify | Any authenticated user in current route | Verifies the local chain. Production currently has a documented mismatch at sequence 1; do not treat it as passing until fixed. |
| GET /api/admin/alerts | Admin only (router-level middleware) | View repeated-denial and document-probing alerts. |
| GET /api/admin/metrics | Admin only (router-level middleware) | Aggregate document, audit and user metrics. |
| POST /api/admin/users/:id/toggle | Admin only (router-level middleware) | Activate/deactivate a user; cannot toggle self through this route. |
| POST /api/ai/recommend | Any authenticated user in current route; validate document ownership before passing a document ID | Generate rule-based sensitivity/recipient advice. It must not grant permissions automatically. |
| POST /api/ai/confirm | Any authenticated user at route level; service must verify caller owns document and advisory | Apply only the caller-confirmed decision. Test owner/advisory binding carefully. |

## Important implementation caveats

- Several routes rely on service-level checks rather than route-level role middleware. Verify the service implementation and tests for every row marked service must enforce.
- CORS currently reflects origins (origin: true) with credentials; use a strict origin allowlist.
- Middleware accepts a token in the query string as well as a Bearer header. Remove query-string token support before production.
- The deployed audit verifier has returned valid: false at sequence 1. Root cause is unresolved.
- The local file-storage directory is not shown to be persistent across Render redeploys.
- Some existing security tests use the legacy SQLite test app. They do not alone prove that the PostgreSQL production routes are safe.

## Schema

The current PostgreSQL schema/setup script is server/src/db/migrations/001_initial_schema.sql. For a clean setup, configure DATABASE_URL, JWT_SECRET, and AUDIT_HMAC_SECRET in the environment before running the PostgreSQL migration and seed scripts. Never commit real secrets.