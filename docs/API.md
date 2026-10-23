# TrustVault API and Authorization Reference

This document reflects the Express route mounts and handlers on the `deploy-postgres` branch. All endpoints use the base path shown below. Unless noted as public, send a bearer token:

```http
Authorization: Bearer <JWT>
```

A valid token proves identity, not document permission. Document operations must still pass the service-level ownership/grant checks. Responses and status codes can vary with validation and service errors.

## Health and authentication

| Method | Endpoint | Who may call it | Purpose / notes |
|---|---|---|---|
| GET | `/api/health` | Public | Service health response. |
| POST | `/api/auth/login` | Public | JSON body: `email`, `password`; returns login result/token on success. Invalid input: 400; invalid credentials: 401; deactivated account: 403. |
| GET | `/api/auth/me` | Any authenticated user | Return the current authenticated user. |
| GET | `/api/auth/users` | Any authenticated user | List users for permission selection. Treat the result as account metadata, not document access. |

## Documents

All `/api/documents` routes require authentication.

| Method | Endpoint | Who may call it | Purpose / notes |
|---|---|---|---|
| GET | `/api/documents` | Any authenticated user | Search/list documents visible to the caller. Optional query parameters include `q`, `category`, `ownerId`, `fromDate`, `toDate`, `limit`, and `offset`. Results must be access-filtered by the service. |
| POST | `/api/documents` | Owner or admin role | Multipart upload; field `file` plus `title`, `category`, optional `description`, optional `classification` (`Public`, `Internal`, `Restricted`, `Confidential`). |
| GET | `/api/documents/:id` | Authenticated user with access to that document | Retrieve metadata; service checks access. |
| GET | `/api/documents/:id/download` | Authenticated user with view/edit access or owner | Download file through backend; service checks current access. The response uses attachment and no-store/security headers. |
| PUT | `/api/documents/:id` | Authenticated user authorized by document service | Update supported metadata and/or upload a replacement file. The service decides whether the caller may edit. |
| DELETE | `/api/documents/:id` | Authenticated user authorized by document service | Delete a document; service-level ownership/authorization applies. |

## Per-document permissions

All permission routes require authentication. The service enforces who may manage a document's grants; callers should expect a 403 when they do not have the required authority.

| Method | Endpoint | Who may call it | Purpose / request |
|---|---|---|---|
| GET | `/api/documents/:id/permissions` | Document owner / authorized manager | List grants for the document. |
| POST | `/api/documents/:id/permissions` | Document owner / authorized manager | JSON body: `{ "userId": "<UUID>", "permissionLevel": "view" | "edit" }`; creates or updates a grant according to service rules. |
| DELETE | `/api/documents/:id/permissions/:userId` | Document owner / authorized manager | Revoke the specified user's grant. Subsequent requests should be re-authorized against current database state. |

## Audit and administration

| Method | Endpoint | Who may call it | Purpose / notes |
|---|---|---|---|
| GET | `/api/audit` | Admin; document owner only for an owned `documentId`; viewers denied | List audit events. Owners must supply `documentId`; optional filters include `action`, `status`, `actorId`, `limit`, and `offset`. |
| GET | `/api/audit/verify` | Any authenticated user in the current route code | Runs chain verification. This endpoint is currently not restricted to admins at the router level. |
| GET | `/api/admin/alerts` | Admin only | Retrieve security alerts. |
| GET | `/api/admin/metrics` | Admin only | Retrieve document, user, and audit metrics. |
| POST | `/api/admin/users/:id/toggle` | Admin only | Activate/deactivate a user; an admin cannot toggle their own account through this endpoint. |

## AI access advisor

Both endpoints require authentication. Recommendation and confirmation service rules still apply.

| Method | Endpoint | Who may call it | Purpose / request |
|---|---|---|---|
| POST | `/api/ai/recommend` | Authenticated user; document-specific authorization depends on supplied document and service checks | JSON body: `documentTitle`, `category`, optional `description`, optional UUID `documentId`. Returns an advisory. |
| POST | `/api/ai/confirm` | Authenticated user subject to service authorization | JSON body: UUID `documentId`, UUID `advisoryId`, `decision` (`ACCEPTED`, `REJECTED`, `MODIFIED`), and `confirmedGrants` array containing UUID `userId` and `permissionLevel` (`view` or `edit`). |

## Common responses

- `400`: request validation or invalid operation.
- `401`: missing/invalid authentication or invalid login credentials.
- `403`: authenticated caller lacks required role or document permission.
- `404`: resource not found (where the handler/service returns that status).
- `500`: unexpected server-side failure.

## Known verification limitation

As of the current submission revision, production `GET /api/audit/verify` has returned `valid: false`, `brokenAt: 1`, with `Audit record hash mismatch`. The cause has not yet been established. Do not describe the production audit chain as successfully verified until this is diagnosed and a successful verification is observed. A mismatch alone does not prove malicious tampering.

## Source of truth

Route mounts: `server/src/app.ts`. Handler and authorization details: `server/src/routes/` and `server/src/services/*pg.ts`. If implementation changes, update this table and re-check authorization before claiming an endpoint is restricted.
