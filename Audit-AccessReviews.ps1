<#
.SYNOPSIS
    Quick PowerShell access-review check for stale and privileged accounts.
.DESCRIPTION
    Flags accounts by days since last logon and role, then exports a CSV for
    access certification review. Uses a small built-in sample set; swap the
    $Users array for Get-ADUser output to run it against a real directory.
.AUTHOR
    Elazar Luis Ferrer
#>

$ReportPath = ".\Access_Review_Report_$(Get-Date -Format 'yyyyMMdd').csv"

$Users = @(
    [PSCustomObject]@{ UserName="jdoe";   Email="jane.doe@enterprise.local";    Role="Standard"; LastLogin="2026-08-10"; Status="Active" },
    [PSCustomObject]@{ UserName="asmith"; Email="alex.smith@enterprise.local";  Role="Admin";    LastLogin="2026-02-15"; Status="Active" },
    [PSCustomObject]@{ UserName="bwayne"; Email="bruce.wayne@enterprise.local"; Role="Admin";    LastLogin="2025-11-01"; Status="Active" },
    [PSCustomObject]@{ UserName="ckent";  Email="clark.kent@enterprise.local";  Role="Standard"; LastLogin="2026-08-14"; Status="Active" }
)

Write-Host "[INFO] Initiating Access Certification Review..." -ForegroundColor Cyan

$AuditResults = foreach ($User in $Users) {
    $DaysInactive = (New-TimeSpan -Start (Get-Date $User.LastLogin) -End (Get-Date)).Days
    $Flag = "Compliant"

    if ($User.Role -eq "Admin" -and $DaysInactive -gt 90) {
        $Flag = "CRITICAL: Stale Admin Account"
    } elseif ($DaysInactive -gt 90) {
        $Flag = "WARNING: Stale User Account"
    } elseif ($User.Role -eq "Admin") {
        $Flag = "REVIEW: Privileged Access Check"
    }

    [PSCustomObject]@{
        UserName       = $User.UserName
        Email          = $User.Email
        Role           = $User.Role
        LastLogin      = $User.LastLogin
        DaysInactive   = $DaysInactive
        ComplianceFlag = $Flag
    }
}

$AuditResults | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding utf8
Write-Host "[SUCCESS] Access Review complete. Compliance report saved to $ReportPath" -ForegroundColor Green
$AuditResults | Format-Table -AutoSize
