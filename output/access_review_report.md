# Quarterly Access Review Report - Q3 2026

**Scope:** 62 directory accounts reconciled against HR roster (60 employees) and the approved RBAC matrix (7 roles).  
**Result:** 17 findings across 17 accounts ({'MEDIUM': 9, 'HIGH': 5, 'CRITICAL': 3}); 45 accounts clean.

All data is synthetic - this simulates the quarterly review procedure in [docs/access_review_procedure.md](../docs/access_review_procedure.md).

## Findings by check

### C1_ORPHANED_ACCOUNT - CRITICAL (3 findings)

- **lvargas2** (Logan Vargas, IT Administrator) - Terminated 2026-06-10 but account still enabled (21 days exposed). *Action:* Disable immediately, revoke sessions/tokens, audit activity since termination date
- **tyilmaz3** (Taylor Yilmaz, IT Administrator) - Terminated 2026-03-07 but account still enabled (116 days exposed). *Action:* Disable immediately, revoke sessions/tokens, audit activity since termination date
- **cquintero4** (Cameron Quintero, Physician) - Terminated 2026-05-09 but account still enabled (53 days exposed). *Action:* Disable immediately, revoke sessions/tokens, audit activity since termination date

### C2_PRIVILEGE_CREEP - HIGH (5 findings)

- **akowalski6** (Alex Kowalski, Registration Clerk) - Groups outside 'Registration Clerk' entitlement: GRP_Domain_Admins. *Action:* Confirm business need with manager; remove excess membership or document exception
- **qyilmaz6** (Quinn Yilmaz, Billing Specialist) - Groups outside 'Billing Specialist' entitlement: GRP_EHR_Orders. *Action:* Confirm business need with manager; remove excess membership or document exception
- **cumar4** (Casey Umar, Registration Clerk) - Groups outside 'Registration Clerk' entitlement: GRP_Helpdesk_Tools. *Action:* Confirm business need with manager; remove excess membership or document exception
- **dzhang5** (Dana Zhang, Physician) - Groups outside 'Physician' entitlement: GRP_HRIS. *Action:* Confirm business need with manager; remove excess membership or document exception
- **eivanov2** (Emerson Ivanov, Registration Clerk) - Groups outside 'Registration Clerk' entitlement: GRP_EHR_Clinical. *Action:* Confirm business need with manager; remove excess membership or document exception

### C3_PRIV_NO_MFA - HIGH (3 findings)

- **aotieno5** (Alex Otieno, IT Support) - Privileged member (GRP_Workstation_Admins) not MFA-enrolled. *Action:* Enforce MFA enrollment before next logon; conditional-access block until enrolled
- **lrossi2** (Logan Rossi, IT Administrator) - Privileged member (GRP_Domain_Admins, GRP_Workstation_Admins) not MFA-enrolled. *Action:* Enforce MFA enrollment before next logon; conditional-access block until enrolled
- **malvarez4** (Morgan Alvarez, IT Administrator) - Privileged member (GRP_Domain_Admins, GRP_Workstation_Admins) not MFA-enrolled. *Action:* Enforce MFA enrollment before next logon; conditional-access block until enrolled

### C4_UNOWNED_SERVICE - MEDIUM (2 findings)

- **svc_backup_legacy** (svc_backup_legacy, n/a) - Service account with no registered owner and interactive logon. *Action:* Assign owner, rotate credential, restrict to non-interactive logon
- **svc_faxgateway** (svc_faxgateway, n/a) - Service account with no registered owner and interactive logon. *Action:* Assign owner, rotate credential, restrict to non-interactive logon

### C5_DORMANT_ACCOUNT - MEDIUM (4 findings)

- **dxu3** (Drew Xu, Physician) - No logon in 156 days (threshold 90). *Action:* Confirm employment status/leave; disable if unused, re-enable on validated request
- **dnguyen** (Drew Nguyen, Nurse) - No logon in 191 days (threshold 90). *Action:* Confirm employment status/leave; disable if unused, re-enable on validated request
- **mchen4** (Morgan Chen, Registration Clerk) - No logon in 208 days (threshold 90). *Action:* Confirm employment status/leave; disable if unused, re-enable on validated request
- **dsilva** (Dana Silva, Nurse) - No logon in 165 days (threshold 90). *Action:* Confirm employment status/leave; disable if unused, re-enable on validated request

## Root-cause themes

1. **Deprovisioning gap** - orphaned accounts mean HR termination events are not reliably triggering directory disablement. Recommend automating the leaver step of the joiner-mover-leaver workflow (HR feed -> directory), not adding more manual checks.
2. **Entitlement drift** - privilege creep findings cluster around transfers: access accumulates because the *mover* step grants new access without removing old. Recommend role-based re-provisioning on department change.
3. **MFA enforcement** - privileged access without MFA is a standing conditional-access policy gap, not an individual-user problem.