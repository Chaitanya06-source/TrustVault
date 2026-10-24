# TrustVault Five-Minute Demo Script

**This file is a recording plan, not a recorded video.** Record the real deployed application and link the actual video in the submission form only after reviewing it. Do not edit out failed security checks or present mock results as production behaviour.

## Before recording

- Open the deployed frontend in a private/incognito window.
- Confirm the backend health URL responds.
- Have demo credentials ready, but do not show environment variables, database credentials, JWTs or HMAC secrets.
- Use only seeded/demo documents, never real confidential files.
- If audit verification still reports a mismatch, show the result and state that it is an unresolved limitation. Do not claim the audit chain passed.

## Timeline (target 5 minutes)

**0:00–0:30 — Problem and architecture**
Explain TrustVault's goal: named per-document permissions, backend-enforced access, and an audit ledger. Briefly show frontend, API, Neon PostgreSQL and the current file-storage design. State that persistence across redeploys must be verified.

**0:30–1:10 — Roles**
Log in as an owner and show document listing. Explain that admin is not automatically a document-content owner. If role switching is implemented as a demo shortcut, disclose that it is a demo feature and not an identity provider.

**1:10–2:00 — Explicit sharing**
Show a document owned by the demo owner. Grant a named viewer view permission. Log in as the viewer and show the granted document is available. Do not expose other users' private titles.

**2:00–2:45 — Denial and revocation**
Attempt to access an ungranted document using the viewer's normal UI or a safe API request. Show the server denial. Revoke the previously granted permission and repeat the request. Explain that revocation blocks subsequent requests but cannot recall bytes already downloaded or necessarily cancel a transfer already in progress.

**2:45–3:35 — Audit trail**
Show the audit UI or API for the relevant grant/revoke and denied attempt. Run the verifier only if the demo environment is safe. If it reports the known sequence-1 mismatch, state that the verifier is currently failing and that this is a known unfinished issue.

**3:35–4:20 — Upload validation and advisor**
Show a benign allowed sample upload or validation test. Explain that ZIP signature checks for .docx/.xlsx are limited and are not malware scanning. Describe the advisor as rule/keyword-based if that is what the deployed code uses; demonstrate that a human confirmation is required before any grant.

**4:20–5:00 — Tests and honest limitations**
Show the actual command output from the test run and identify which tests use the legacy SQLite harness versus PostgreSQL. Finish with known limitations: audit verifier mismatch, no login rate limiting, CORS allowlist still needed, and persistence of local uploads across redeploys not established.

## After recording

- Watch the full recording once.
- Confirm every shown action actually works on the current deployed version.
- Upload the real video to a stable link with evaluator access.
- Add that exact link to the submission form/README. Do not invent a video URL.