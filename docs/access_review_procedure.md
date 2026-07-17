# User Access Review Procedure (Joiner-Mover-Leaver)

The access review is the *detective* control; the JML lifecycle is the *preventive*
one. Findings in the review are symptoms of JML gaps — the report's root-cause
section always maps back here.

## Lifecycle stages

| Stage | Trigger | Required actions | Failure mode this review catches |
|---|---|---|---|
| **Joiner** | HR hire record | Provision account from role template (RBAC matrix), MFA enrollment before first PHI access | Ad-hoc group grants outside the template (C2) |
| **Mover** | Department/role change | Re-provision from *new* role template — remove old entitlements, then add new | Privilege creep: access accumulates across transfers (C2) |
| **Leaver** | HR termination record | Same-day disable, session/token revocation, mailbox delegation, hardware recovery | Orphaned accounts (C1) — the highest-risk finding class |

## Quarterly review cycle

1. **Extract** — pull directory export (accounts, group membership, MFA state, last logon) and current HR roster. The HR system is the source of truth for *who works here*; the RBAC matrix is the source of truth for *what each role gets*.
2. **Reconcile** — run `src/run_access_review.py`. Checks C1–C5 (orphaned, creep, privileged-no-MFA, unowned service accounts, dormant).
3. **Certify** — route C2 findings to the account's manager: confirm business need or remove. Exceptions require documented approval with an expiry date — an exception without an expiry is just drift with paperwork.
4. **Remediate** — C1 via `remediation/Disable-OrphanedAccounts.ps1` (dry-run first, always). Each action lands in a timestamped audit log.
5. **Report** — findings, remediation status, and root-cause themes to the security owner. Trend the counts quarter-over-quarter: a healthy program's C1 count goes to zero and stays there; C2 recurring at the same rate means the mover process is still broken.

## Control mapping

| Check | HIPAA Security Rule | NIST CSF 2.0 |
|---|---|---|
| C1 Orphaned | §164.308(a)(3)(ii)(C) Termination procedures | PR.AA-01, ID.AM-08 |
| C2 Privilege creep | §164.308(a)(4) Access management; minimum necessary | PR.AA-05 |
| C3 Privileged no MFA | §164.312(d) Person/entity authentication | PR.AA-03 |
| C4 Unowned service acct | §164.308(a)(3) Workforce security | ID.AM-01, PR.AA-01 |
| C5 Dormant | §164.308(a)(1)(ii)(D) Activity review | DE.CM-01 |

## Design decisions

**Why reconcile against HR, not against the directory's own state?** A directory can be internally consistent and still wrong — only an external source of truth exposes orphans. **Why severity-rank instead of listing?** Reviews die when every finding looks equally urgent; CRITICAL means "attack surface today," MEDIUM means "hygiene this sprint." **Why is remediation gated behind a dry-run flag?** Identity remediation is itself a change to production access — it gets the same review discipline as the access it's cleaning up.
