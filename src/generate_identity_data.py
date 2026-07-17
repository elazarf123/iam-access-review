"""
generate_identity_data.py
Builds the three inputs a real access review consumes:

  data/hr_roster.csv       - source of truth from HR (who works here, in what role)
  data/accounts_export.csv - directory export (accounts, groups, MFA, last logon)
  data/rbac_matrix.csv     - approved role -> group entitlement mapping

Six control failures are planted for the audit to find:
  3 orphaned accounts (terminated, still enabled)
  4 dormant accounts (no logon > 90 days)
  5 privilege-creep accounts (groups outside their role's RBAC entitlement)
  3 privileged users without MFA
  2 ownerless service accounts with interactive logon

Seeded RNG - fully reproducible. All identities are fictitious.
"""

import csv
import random
from datetime import date, timedelta
from pathlib import Path

random.seed(23)

DATA = Path(__file__).resolve().parent.parent / "data"
DATA.mkdir(exist_ok=True)
TODAY = date(2026, 7, 1)

ROLES = {
    # role: (dept, allowed groups)
    "Registration Clerk": ("Front Desk", ["GRP_EHR_Registration", "GRP_Printers", "GRP_VPN_Users"]),
    "Nurse": ("Clinical", ["GRP_EHR_Clinical", "GRP_Printers", "GRP_VPN_Users"]),
    "Physician": ("Clinical", ["GRP_EHR_Clinical", "GRP_EHR_Orders", "GRP_Printers", "GRP_VPN_Users"]),
    "Billing Specialist": ("Revenue Cycle", ["GRP_EHR_Billing", "GRP_Claims_Portal", "GRP_VPN_Users"]),
    "IT Support": ("IT", ["GRP_Helpdesk_Tools", "GRP_Workstation_Admins", "GRP_VPN_Users"]),
    "IT Administrator": ("IT", ["GRP_Domain_Admins", "GRP_Helpdesk_Tools", "GRP_Workstation_Admins", "GRP_VPN_Users"]),
    "HR Coordinator": ("HR", ["GRP_HRIS", "GRP_Printers", "GRP_VPN_Users"]),
}
PRIVILEGED_GROUPS = {"GRP_Domain_Admins", "GRP_Workstation_Admins", "GRP_EHR_Orders"}
ALL_GROUPS = sorted({g for _, (_, groups) in ROLES.items() for g in groups})

FIRST = ["Alex", "Sam", "Jordan", "Casey", "Riley", "Morgan", "Avery", "Quinn", "Dana",
         "Jamie", "Taylor", "Cameron", "Drew", "Emerson", "Finley", "Harper", "Kendall",
         "Logan", "Marley", "Noel", "Parker", "Reese", "Sage", "Skyler", "Tatum"]
LAST = ["Nguyen", "Okafor", "Silva", "Kowalski", "Haddad", "Ivanov", "Marsh", "Otieno",
        "Petrov", "Quintero", "Rossi", "Sato", "Tanaka", "Umar", "Vargas", "Weber",
        "Xu", "Yilmaz", "Zhang", "Alvarez", "Bishop", "Chen", "Dietrich", "Ellison", "Fuentes"]

roster, accounts = [], []
used = set()

def new_name():
    while True:
        n = (random.choice(FIRST), random.choice(LAST))
        if n not in used:
            used.add(n)
            return n

def sam(first, last, i):
    return f"{first[0].lower()}{last.lower()}{i%7 if i%7 else ''}"

for i in range(1, 61):
    first, last = new_name()
    role = random.choice(list(ROLES))
    dept, allowed = ROLES[role]
    terminated = i % 15 == 0                      # 4 terminated employees
    term_date = (TODAY - timedelta(days=random.randint(10, 120))).isoformat() if terminated else ""
    emp = {
        "employee_id": f"E{1000+i}", "first_name": first, "last_name": last,
        "department": dept, "role": role,
        "status": "Terminated" if terminated else "Active", "termination_date": term_date,
    }
    roster.append(emp)

    groups = list(allowed)
    acct_enabled = True
    last_logon = TODAY - timedelta(days=random.randint(0, 21))

    if terminated:
        # PLANT: 3 of the 4 terminated users were never disabled (orphaned)
        acct_enabled = i != 15
        last_logon = date.fromisoformat(term_date) - timedelta(days=random.randint(0, 5))

    accounts.append({
        "sam_account": sam(first, last, i), "employee_id": emp["employee_id"],
        "display_name": f"{first} {last}", "enabled": str(acct_enabled).upper(),
        "groups": ";".join(sorted(groups)),
        "mfa_enrolled": "TRUE",
        "last_logon": last_logon.isoformat(),
        "account_type": "user", "owner": emp["employee_id"],
    })

active_accts = [a for a in accounts if a["enabled"] == "TRUE"
                and roster[int(a["employee_id"][1:]) - 1001]["status"] == "Active"]

# PLANT: dormant accounts (4)
for a in random.sample(active_accts, 4):
    a["last_logon"] = (TODAY - timedelta(days=random.randint(95, 220))).isoformat()

# PLANT: privilege creep (5) - add a group the role is NOT entitled to
for a in random.sample(active_accts, 5):
    emp = roster[int(a["employee_id"][1:]) - 1001]
    allowed = set(ROLES[emp["role"]][1])
    extra = random.choice([g for g in ALL_GROUPS if g not in allowed] + ["GRP_Domain_Admins"])
    a["groups"] = ";".join(sorted(set(a["groups"].split(";")) | {extra}))

# PLANT: privileged users without MFA (3)
priv_accts = [a for a in active_accts if set(a["groups"].split(";")) & PRIVILEGED_GROUPS]
for a in random.sample(priv_accts, min(3, len(priv_accts))):
    a["mfa_enrolled"] = "FALSE"

# PLANT: ownerless service accounts with interactive logon (2)
for name in ["svc_backup_legacy", "svc_faxgateway"]:
    accounts.append({
        "sam_account": name, "employee_id": "", "display_name": name,
        "enabled": "TRUE", "groups": "GRP_VPN_Users",
        "mfa_enrolled": "FALSE",
        "last_logon": (TODAY - timedelta(days=random.randint(1, 30))).isoformat(),
        "account_type": "service", "owner": "",
    })

with open(DATA / "hr_roster.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=roster[0].keys()); w.writeheader(); w.writerows(roster)
with open(DATA / "accounts_export.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=accounts[0].keys()); w.writeheader(); w.writerows(accounts)
with open(DATA / "rbac_matrix.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["role", "allowed_groups"])
    for role, (_, groups) in ROLES.items():
        w.writerow([role, ";".join(sorted(groups))])

print(f"Wrote {len(roster)} employees, {len(accounts)} accounts, {len(ROLES)} RBAC roles -> {DATA}")
