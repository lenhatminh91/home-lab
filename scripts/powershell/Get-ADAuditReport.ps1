<#
.SYNOPSIS
    Audits Active Directory user accounts for common security risks.

.DESCRIPTION
    Checks performed:
      - Members of privileged groups (Domain/Enterprise/Schema Admins, Administrators)
      - Accounts that are currently locked out
      - Accounts with PasswordNotRequired set
      - Accounts whose password never expires
      - Enabled accounts that have not logged on in -InactiveDays days (or never)
      - Disabled accounts still present in the OU

    Results are printed as a summary and exported to CSV and HTML.

    Note: LastLogonDate comes from lastLogonTimestamp, which only replicates
    roughly every 9-14 days, so it is accurate enough for "inactive for 30+ days"
    but not for "logged on today".

.EXAMPLE
    .\Get-ADAuditReport.ps1
.EXAMPLE
    .\Get-ADAuditReport.ps1 -InactiveDays 60
#>
[CmdletBinding()]
param(
    [int]$InactiveDays  = 30,
    [string]$SearchBase = "OU=LabCorp,DC=lab,DC=local",
    [string]$OutputDir  = "C:\Scripts\Reports"
)

Import-Module ActiveDirectory -ErrorAction Stop
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding {
    param($Severity, $Check, $Account, $Detail)
    $findings.Add([pscustomobject]@{
        Severity = $Severity
        Check    = $Check
        Account  = $Account
        Detail   = $Detail
    })
}

# 1. Privileged group membership (whole domain) --------------------------
$privGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators'
foreach ($g in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop |
                   Where-Object objectClass -eq 'user'
    } catch { continue }
    foreach ($m in $members) {
        Add-Finding 'Info' 'Privileged group member' $m.SamAccountName "Member of $g"
    }
}

# 2. Locked-out accounts -------------------------------------------------
Search-ADAccount -LockedOut -UsersOnly | ForEach-Object {
    Add-Finding 'High' 'Account locked out' $_.SamAccountName 'Possible brute force or forgotten password'
}

# 3. Password not required -----------------------------------------------
Get-ADUser -Filter 'PasswordNotRequired -eq $true' -SearchBase $SearchBase | ForEach-Object {
    Add-Finding 'High' 'Password not required' $_.SamAccountName 'Account may have an empty password'
}

# 4. Password never expires ----------------------------------------------
Get-ADUser -Filter 'PasswordNeverExpires -eq $true' -SearchBase $SearchBase | ForEach-Object {
    Add-Finding 'Medium' 'Password never expires' $_.SamAccountName 'Password is never forced to rotate'
}

# 5. Inactive enabled accounts -------------------------------------------
$cutoff = (Get-Date).AddDays(-$InactiveDays)
Get-ADUser -Filter 'Enabled -eq $true' -SearchBase $SearchBase -Properties LastLogonDate, whenCreated |
    ForEach-Object {
        if (-not $_.LastLogonDate) {
            Add-Finding 'Low' 'Never logged on' $_.SamAccountName ("Created {0:yyyy-MM-dd}" -f $_.whenCreated)
        } elseif ($_.LastLogonDate -lt $cutoff) {
            Add-Finding 'Medium' "Inactive > $InactiveDays days" $_.SamAccountName ("Last logon {0:yyyy-MM-dd}" -f $_.LastLogonDate)
        }
    }

# 6. Disabled accounts ---------------------------------------------------
Search-ADAccount -AccountDisabled -UsersOnly -SearchBase $SearchBase | ForEach-Object {
    Add-Finding 'Low' 'Disabled account' $_.SamAccountName 'Consider removing if no longer needed'
}

# --- Output -------------------------------------------------------------
$order  = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
$sorted = $findings | Sort-Object { $order[$_.Severity] }, Check, Account

Write-Host "`n=== AD Audit Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm') ===" -ForegroundColor Cyan
$sorted | Group-Object Severity | ForEach-Object { Write-Host ("{0,-7} {1}" -f $_.Name, $_.Count) }
$sorted | Format-Table -AutoSize

$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvPath  = Join-Path $OutputDir "ADAudit_$stamp.csv"
$htmlPath = Join-Path $OutputDir "ADAudit_$stamp.html"

$sorted | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$css = @"
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b2631}
h1{font-size:20px} table{border-collapse:collapse;width:100%}
th,td{border:1px solid #d5dbe1;padding:6px 10px;text-align:left;font-size:13px}
th{background:#eef2f5}
</style>
"@
$sorted | ConvertTo-Html -Head $css `
    -PreContent "<h1>AD Audit Report - lab.local</h1><p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME</p>" |
    Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host "CSV : $csvPath"
Write-Host "HTML: $htmlPath"
