<#
.SYNOPSIS
    Bulk-creates Active Directory users from a CSV file.

.DESCRIPTION
    For each row in the CSV, the script:
      - checks that the department OU exists under OU=LabCorp
      - skips the user if the SamAccountName already exists
      - creates the user in the department OU
      - adds the user to the department group (GRP_<Department>)
      - writes every action to a timestamped log file

    The initial password is never stored in the script or the CSV;
    it is asked for at run time as a SecureString.

.PARAMETER CsvPath
    CSV with columns: FirstName,LastName,SamAccountName,Department,Title

.EXAMPLE
    .\New-LabUsers.ps1 -CsvPath .\users.csv -WhatIf
    Shows what would be created without changing anything.

.EXAMPLE
    .\New-LabUsers.ps1 -CsvPath .\users.csv
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$CsvPath,

    [string]$DomainDN    = "DC=lab,DC=local",
    [string]$UpnSuffix   = "lab.local",
    [string]$ParentOU    = "OU=LabCorp",
    [string]$LogDir      = "C:\Scripts\Logs",

    [securestring]$InitialPassword
)

Import-Module ActiveDirectory -ErrorAction Stop

# --- Logging -----------------------------------------------------------
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$LogFile = Join-Path $LogDir ("New-LabUsers_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $line = "{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}" -f (Get-Date), $Level, $Message
    Add-Content -Path $LogFile -Value $line
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

# --- Input -------------------------------------------------------------
if (-not (Test-Path $CsvPath)) { throw "CSV file not found: $CsvPath" }
$rows = Import-Csv -Path $CsvPath

$required = 'FirstName','LastName','SamAccountName','Department','Title'
$missing  = $required | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name }
if ($missing) { throw "CSV is missing column(s): $($missing -join ', ')" }

if (-not $InitialPassword -and -not $WhatIfPreference) {
    $InitialPassword = Read-Host -AsSecureString "Initial password for new users"
}

Write-Log "Started. CSV: $CsvPath ($($rows.Count) rows)"
$stats = @{ Created = 0; Skipped = 0; Failed = 0 }

# --- Main loop ---------------------------------------------------------
foreach ($row in $rows) {
    $sam   = $row.SamAccountName.Trim().ToLower()
    $dept  = $row.Department.Trim()
    $ouDN  = "OU=$dept,$ParentOU,$DomainDN"
    $group = "GRP_$dept"
    $name  = "$($row.FirstName) $($row.LastName)".Trim()

    # 1. Department OU must exist
    try {
        Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "SKIP $sam - OU not found: $ouDN" 'WARN'
        $stats.Skipped++; continue
    }

    # 2. Do not touch existing accounts
    if (Get-ADUser -Filter "SamAccountName -eq '$sam'") {
        Write-Log "SKIP $sam - user already exists" 'WARN'
        $stats.Skipped++; continue
    }

    # 3. Create the user
    if ($PSCmdlet.ShouldProcess("$name ($sam) in $ouDN", "Create AD user")) {
        try {
            $params = @{
                Name                  = $name
                GivenName             = $row.FirstName
                Surname               = $row.LastName
                DisplayName           = $name
                SamAccountName        = $sam
                UserPrincipalName     = "$sam@$UpnSuffix"
                Title                 = $row.Title
                Department            = $dept
                Path                  = $ouDN
                AccountPassword       = $InitialPassword
                Enabled               = $true
                ChangePasswordAtLogon = $true
                ErrorAction           = 'Stop'
            }
            New-ADUser @params
            Write-Log "CREATED $sam ($name) in $ouDN"
            $stats.Created++
        } catch {
            Write-Log "FAILED $sam - $($_.Exception.Message)" 'ERROR'
            $stats.Failed++; continue
        }

        # 4. Add to the department group
        try {
            Add-ADGroupMember -Identity $group -Members $sam -ErrorAction Stop
            Write-Log "ADDED $sam to $group"
        } catch {
            Write-Log "Could not add $sam to $group - $($_.Exception.Message)" 'WARN'
        }
    }
}

Write-Log ("Finished. Created: {0}  Skipped: {1}  Failed: {2}" -f $stats.Created, $stats.Skipped, $stats.Failed)
Write-Host "Log file: $LogFile"
