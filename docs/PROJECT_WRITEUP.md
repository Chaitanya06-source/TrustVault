# TrustVault — Short Project Write-up

## What I built

TrustVault is a document-sharing application with authenticated roles, per-document view and edit grants, upload validation, backend-mediated downloads, an administrative activity view, and an audit-chain implementation. The backend uses Node.js/TypeScript and PostgreSQL for the current deployment branch. The frontend is hosted separately.

## Permission model

The model is owner-centric: a document owner can share a specific document with a named user at a specific permission level and revoke that grant. A viewer's access should come from ownership or an explicit grant, not from knowing a document ID or seeing a UI control. The administrator role provides administrative visibility/operations but does not automatically grant access to confidential document bytes. Authorization must be enforced by the server for every protected endpoint.

## How AI was used and where it was wrong

AI assistance was used for implementation and security design. The development record includes cases where a proposed pre-signed URL design conflicted with immediate revocation, a simple SQL audit table lacked tamper evidence, trusting a client MIME type was insufficient, and automatic permission widening would violate human approval. The current advisory component should be described as rule/keyword-based unless a deployed model integration is demonstrated. The prompt log was consolidated after development and is not a claim that every entry was written contemporaneously.

## What I deliberately did not build

This challenge release does not establish durable object storage for uploaded bytes across Render redeploys. It has no independent external anchor for the latest audit-chain head, no confirmed login rate limiting, and no verified cancellation of an already-started download after revocation. Full ZIP/OpenXML inspection and malware scanning are also not implemented. These gaps are listed rather than described as completed features.

## What is unfinished

The deployed audit verifier has returned valid: false at sequence 1 with an audit record hash mismatch. Its cause is unresolved. Some automated tests exercise the legacy SQLite test app rather than the PostgreSQL services used in deployment. The new recipient-directory authorization regression test must be run, and PostgreSQL integration tests must cover the deployed routes before security can be considered verified. A five-minute demo video must be recorded and linked separately; the repository's demo script is only a plan.

## How I would improve it next

1. Diagnose the audit mismatch read-only and add PostgreSQL integration tests before changing any production records.
2. Anchor the latest audit sequence/hash outside the application database.
3. Restrict CORS to known origins and remove query-string JWT support.
4. Add login rate limiting, stricter Office-package validation, and a persistent private object-storage backend.
5. Test authorization-check removal against the actual PostgreSQL download route.