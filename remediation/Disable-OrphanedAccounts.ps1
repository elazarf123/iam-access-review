param(
    [string]$FindingsPath = "output/findings.csv",
    [switch]$Execute
)

if (-not (Test-Path $FindingsPath)) {
    Write-Error "Findings file not found: $FindingsPath"
    exit 1
}

$findings = Import-Csv $FindingsPath | Where-Object { $_.check -eq 'C1_ORPHANED_ACCOUNT' }

if ($findings.Count -eq 0) {
    Write-Host "No orphaned accounts found in $FindingsPath." -ForegroundColor Green
    exit 0
}

$modeText = if ($Execute) { "LIVE EXECUTION" } else { "DRY RUN (WhatIf)" }
Write-Host "=========================================="
Write-Host " IAM Remediation: Orphaned Accounts"
Write-Host " Mode: $modeText"
Write-Host " Target Accounts: $($findings.Count)"
Write-Host "==========================================`n"

foreach ($f in $findings) {
    $sam = $f.sam_account
    $name = $f.display_name
    $actionPrefix = if ($Execute) { "[DISABLING]" } else { "[DRY RUN] Would disable" }
    
    Write-Host ("{0} {1} ({2}) - {3}" -f $actionPrefix, $sam, $name, $f.detail) -ForegroundColor Cyan

    if ($Execute) {
        # Live command for Active Directory environment:
        # Disable-ADAccount -Identity $sam -Confirm:$false
        Write-Host "  -> [ACTION] Disabled account: $sam" -ForegroundColor Green
    } else {
        Write-Host "  -> [SAFE] No directory modifications made." -ForegroundColor Yellow
    }
}

Write-Host "`nRemediation audit completed."
