# TrustVault Five-Minute Demo Plan

This is a recording script, not a claim that a video has already been recorded. Record the deployed application in a fresh browser session, avoid showing secrets, and narrate only actions that work during the recording.

## Before recording

- Open the live frontend in an incognito/private window.
- Confirm the backend health endpoint responds.
- Have demo credentials available from the project's seed/setup documentation; do not put production secrets on screen.
- Use demo documents only. Do not upload real confidential information.
- If the audit verifier still reports a mismatch, show it honestly and explain it as unfinished.

## Timeline and narration

### 0:00–0:30 — Problem and architecture
“TrustVault is a document-sharing demo built around server-side authorization. It uses a React/Vite frontend, Express/TypeScript API, Neon PostgreSQL for metadata and audit records, and Supabase Storage for file objects.”

### 0:30–1:10 — Authentication and roles
Sign in with the documented demo accounts, showing the distinction between admin, owner, and viewer. Explain that authentication identifies a user; it does not automatically grant access to every document.

### 1:10–2:05 — Document visibility and permissions
As an owner, show an owned document and its permission controls. Explain the difference between `view` and `edit`. Use an already completed sharing demonstration if you have one; do not spend the recording repeatedly retrying a flaky workflow.

### 2:05–2:45 — Revocation and server-side checks
Explain that each protected request is checked by the backend against current permissions, rather than relying only on hidden UI controls. Mention that the existing automated revocation tests use the local test harness; do not imply they alone prove the production database path.

### 2:45–3:25 — Upload and file handling
Show demo document metadata and explain upload validation, backend-mediated downloads, and private object storage. Do not claim that file validation makes every uploaded file safe.

### 3:25–4:05 — AI access advisor
Show a recommendation if it works in the deployed build. Explain that it suggests least-privilege access and requires a human decision; it should not autonomously widen permissions.

### 4:05–4:40 — Audit trail and honest limitation
Show audit events and the verification result. If verification reports `Audit record hash mismatch`, state: “The verifier currently fails at record 1 in this deployment. I have not treated this as proof of malicious tampering, and I have not hidden the warning. The root cause remains under investigation.” Do not edit or delete records to make the screen look successful.

### 4:40–5:00 — Wrap-up
Summarize the authorization model, the tests and threat model, and the known unfinished audit-verification issue. Close with the repository and live URL.

## Recording checklist

- [ ] Video is approximately five minutes.
- [ ] Live URL and main flows are visible.
- [ ] No secrets, real private files, or personal tokens are shown.
- [ ] Statements match the current deployed behavior.
- [ ] Audit-verification failure, if still present, is disclosed.
- [ ] Add the actual video link to the submission form/README after uploading it.
