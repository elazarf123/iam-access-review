"""
run_access_review.py
Quarterly user-access review: reconciles the directory export against the
HR roster (source of truth) and the approved RBAC matrix.

Checks (each maps to a control - see docs/access_review_procedure.md):

  C1 ORPHANED_ACCOUNT   terminated in HR, still enabled in directory   CRITICAL
  C2 PRIVILEGE_CREEP    member of groups outside role entitlement      HIGH
  C3 PRIV_NO_MFA        privileged-group member without MFA            HIGH
  C4 UNOWNED_SERVICE    service account with no owner on record        MEDIUM
  C5 DORMANT_ACCOUNT    active account, no logon > 90 days             MEDIUM

Outputs:
  output/findings.csv            one row per finding, severity-ranked
  output/access_review_report.md analyst report with remediation actions

Run:  python src/run_access_review.py   (after src/generate_identity_data.py)
"""

from datetime import date
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parent.parent
OUT = BASE / "output"
OUT.mkdir(exist_ok=True)
TODAY = date(2026, 7, 1)
DORMANT_DAYS = 90
PRIVILEGED_GROUPS = {"GRP_Domain_Admins", "GRP_Workstation_Admins", "GRP_EHR_Orders"}

roster = pd.read_csv(BASE / "data" / "hr_roster.csv").fillna("")
accounts = pd.read_csv(BASE / "data" / "accounts_export.csv").fillna("")
rbac = pd.read_csv(BASE / "data" / "rbac_matrix.csv")
allowed_by_role = {r.role: set(r.allowed_groups.split(";")) for r in rbac.itertuples()}

acct = accounts.merge(roster, on="employee_id", how="left").fillna("")
findings = []

def flag(check, severity, row, detail, action):
    findings.append({
        "check": check, "severity": severity,
        "sam_account": row.sam_account,
        "display_name": row.display_name,
        "role": getattr(row, "role", "") or "n/a",
        "detail": detail, "recommended_action": action,
    })

for row in acct.itertuples():
    groups = set(row.groups.split(";")) if row.groups else set()
    # pandas reads TRUE/FALSE as booleans - normalize to be safe either way
    enabled = str(row.enabled).upper() == "TRUE"
    mfa_missing = str(row.mfa_enrolled).upper() == "FALSE"
    days_idle = (TODAY - date.fromisoformat(row.last_logon)).days

    # C1 - orphaned: HR says terminated, directory says enabled
    if row.status == "Terminated" and enabled:
        flag("C1_ORPHANED_ACCOUNT", "CRITICAL", row,
             f"Terminated {row.termination_date} but account still enabled "
             f"({(TODAY - date.fromisoformat(row.termination_date)).days} days exposed)",
             "Disable immediately, revoke sessions/tokens, audit activity since termination date")

    # C2 - privilege creep vs RBAC matrix
    if row.status == "Active" and row.role in allowed_by_role:
        excess = groups - allowed_by_role[row.role]
        if excess:
            sev = "HIGH" if excess & PRIVILEGED_GROUPS else "MEDIUM"
            flag("C2_PRIVILEGE_CREEP", sev, row,
                 f"Groups outside '{row.role}' entitlement: {', '.join(sorted(excess))}",
                 "Confirm business need with manager; remove excess membership or document exception")

    # C3 - privileged without MFA
    if enabled and (groups & PRIVILEGED_GROUPS) and mfa_missing:
        flag("C3_PRIV_NO_MFA", "HIGH", row,
             f"Privileged member ({', '.join(sorted(groups & PRIVILEGED_GROUPS))}) not MFA-enrolled",
             "Enforce MFA enrollment before next logon; conditional-access block until enrolled")

    # C4 - ownerless service account
    if row.account_type == "service" and not row.owner:
        flag("C4_UNOWNED_SERVICE", "MEDIUM", row,
             "Service account with no registered owner and interactive logon",
             "Assign owner, rotate credential, restrict to non-interactive logon")

    # C5 - dormant
    if enabled and row.status == "Active" and days_idle > DORMANT_DAYS:
        flag("C5_DORMANT_ACCOUNT", "MEDIUM", row,
             f"No logon in {days_idle} days (threshold {DORMANT_DAYS})",
             "Confirm employment status/leave; disable if unused, re-enable on validated request")

order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
df = pd.DataFrame(findings).sort_values(["severity", "check"], key=lambda s: s.map(order).fillna(s))
df.to_csv(OUT / "findings.csv", index=False)

# ------------------------------------------------------------------ report
total_accounts = len(accounts)
counts = df["severity"].value_counts().to_dict()
clean = total_accounts - df["sam_account"].nunique()

lines = [
    "# Quarterly Access Review Report - Q3 2026",
    "",
    f"**Scope:** {total_accounts} directory accounts reconciled against HR roster "
    f"({len(roster)} employees) and the approved RBAC matrix ({len(rbac)} roles).  ",
    f"**Result:** {len(df)} findings across {df['sam_account'].nunique()} accounts "
    f"({counts}); {clean} accounts clean.",
    "",
    "All data is synthetic - this simulates the quarterly review procedure in "
    "[docs/access_review_procedure.md](../docs/access_review_procedure.md).",
    "",
    "## Findings by check",
    "",
]
for check, grp in df.groupby("check", sort=False):
    lines.append(f"### {check} - {grp.iloc[0]['severity']} ({len(grp)} findings)")
    lines.append("")
    for _, f in grp.iterrows():
        lines.append(f"- **{f.sam_account}** ({f.display_name}, {f.role}) - {f.detail}. "
                     f"*Action:* {f.recommended_action}")
    lines.append("")

lines += [
    "## Root-cause themes",
    "",
    "1. **Deprovisioning gap** - orphaned accounts mean HR termination events are not "
    "reliably triggering directory disablement. Recommend automating the leaver step "
    "of the joiner-mover-leaver workflow (HR feed -> directory), not adding more manual checks.",
    "2. **Entitlement drift** - privilege creep findings cluster around transfers: access "
    "accumulates because the *mover* step grants new access without removing old. "
    "Recommend role-based re-provisioning on department change.",
    "3. **MFA enforcement** - privileged access without MFA is a standing conditional-access "
    "policy gap, not an individual-user problem.",
]
(OUT / "access_review_report.md").write_text("\n".join(lines))

print(df.groupby(["severity", "check"]).size())
print(f"\n{len(df)} findings -> {OUT / 'findings.csv'}")
print(f"Report -> {OUT / 'access_review_report.md'}")
