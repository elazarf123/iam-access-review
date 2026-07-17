<#
.SYNOPSIS
    Remediates C1 (orphaned account) findings from the quarterly access review.

.DESCRIPTION
    Reads output/findings.csv, selects C1_ORPHANED_ACCOUNT rows, and disables
    each account in Active Directory. Defaults to -WhatIf (dry run): remediation
    that touches identities should never run un-reviewed.

    Every action is logged to a timestamped CSV for the audit trail - the
    reviewer's sign-off artifact, not just a courtesy.

.EXAMPLE
    .\Disable-OrphanedAccounts.ps1                 # dry run - shows what would happen
    .\Disable-OrphanedAccounts.ps1 -Execute        # performs disablement + logging

.NOTES
    Requires: ActiveDirectory module, rights to disable accounts in target OUs.
    Portfolio note: written against a synthetic dataset; the pattern (CSV of
    findings in, gated remediation + audit log out) is production-shaped.
#>
[CmdletBinding()]
param(
    [string]$FindingsPath = "$PSScriptRoot\..\output\findings.csv",
    [switch]$Execute
)

$findings = Import-Csv $FindingsPath | Where-Object { $_.check -eq 'C1_ORPHANED_ACCOUNT' }
if (-not $findings) { Write-Host 'No C1 findings to remediate.'; return }

$log = @()
foreach ($f in $findings) {
    $sam = $f.sam_account
    Write-Host ("{0} {1} - {2}" -f ($Execute ? 'DISABLING' : '[DRY RUN] would disable'), $sam, $f.detail)

    if ($Execute) {
        try {
            Disable-ADAccount -Identity $sam -ErrorAction Stop
            # Also revoke refresh tokens if hybrid-joined (Entra ID):
            # Revoke-MgUserSignInSession -UserId "$sam@domain.example"
            $result = 'Disabled'
        }
        catch { $result = "FAILED: $($_.Exception.Message)" }
    }
    else { $result = 'DryRun' }

    $log += [pscustomobject]@{
        Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        SamAccount  = $sam
        Action      = 'Disable-ADAccount'
        Result      = $result
        SourceCheck = $f.check
        Operator    = $env:USERNAME
    }
}

$logPath = "$PSScriptRoot\remediation_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$log | Export-Csv $logPath -NoTypeInformation
Write-Host "Audit log: $logPath"
