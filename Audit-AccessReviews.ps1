<#
.SYNOPSIS
    Identity Access Review & Audit Readiness Engine
.DESCRIPTION
    Scans user group memberships and last login timestamps to flag stale, 
    over-privileged, or unauthorized accounts for compliance certification (SOC2/SOX).
.AUTHOR
    Elazar Luis Ferrer
#>

.\Access_Review_Report_20260816.csv = ".\Access_Review_Report_20260816.csv"
    = @(
    [PSCustomObject]@{ UserName="jdoe"; Email="jane.doe@enterprise.local"; Role="Standard"; LastLogin="2026-08-10"; Status="Active" },
    [PSCustomObject]@{ UserName="asmith"; Email="alex.smith@enterprise.local"; Role="Admin"; LastLogin="2026-02-15"; Status="Active" },
    [PSCustomObject]@{ UserName="bwayne"; Email="bruce.wayne@enterprise.local"; Role="Admin"; LastLogin="2025-11-01"; Status="Active" },
    [PSCustomObject]@{ UserName="ckent"; Email="clark.kent@enterprise.local"; Role="Standard"; LastLogin="2026-08-14"; Status="Active" }
)

Write-Host "[INFO] Initiating Access Certification Review..." -ForegroundColor Cyan
    = foreach (@{UserName=ckent; Email=clark.kent@enterprise.local; Role=Standard; LastLogin=2026-08-14; Status=Active} in    ) {
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
        UserName     = $User.UserName
        Email        = $User.Email
        Role         = $User.Role
        LastLogin    = $User.LastLogin
        DaysInactive = $DaysInactive
        ComplianceFlag = $Flag
    }
}

$AuditResults | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding utf8
Write-Host "[SUCCESS] Access Review complete. Compliance report saved to $ReportPath" -ForegroundColor Green
$AuditResults | Format-Table -AutoSize
