# Audit policy (`LAB - Audit Policy` GPO)

Linked to `lab.local`, so it applies to DC01 and to WS01 in `LabCorp/Workstations`.

Windows logs relatively little by default. These settings enable the events a SOC analyst needs to answer *who logged on, from where, what ran, and what changed*, without turning on every category and burying the useful events in noise.

## Advanced Audit Policy

Path: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies`

| Category | Subcategory | Audit | Key events | Why |
|---|---|---|---|---|
| Account Logon | Credential Validation | Success, Failure | 4776 | NTLM authentication attempts |
| Account Logon | Kerberos Authentication Service | Success, Failure | 4768, 4771 | Domain logons; 4771 = wrong password (brute force) |
| Account Management | User Account Management | Success, Failure | 4720, 4722, 4724, 4738, 4740 | Accounts created, enabled, reset, changed, locked out |
| Account Management | Security Group Management | Success, Failure | 4728, 4732, 4756 | Members added to groups (privilege escalation) |
| Logon/Logoff | Logon | Success, Failure | 4624, 4625 | Successful and failed logons with logon type and source |
| Logon/Logoff | Account Lockout | Failure | 4625 | Logon attempts against locked accounts |
| Logon/Logoff | Special Logon | Success | 4672 | Logons with admin-equivalent privileges |
| Detailed Tracking | Process Creation | Success | 4688 | Every program started |
| Policy Change | Audit Policy Change | Success, Failure | 4719 | Someone turning auditing off |
| DS Access | Directory Service Changes | Success | 5136, 5137 | Changes to AD objects (DC only) |

## Administrative Templates

| Setting | Value | Why |
|---|---|---|
| System > Audit Process Creation > Include command line in process creation events | Enabled | 4688 shows `powershell.exe -enc ...`, not just `powershell.exe` |
| Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging | Enabled | Event 4104 records the script text, including de-obfuscated code |
| Windows Components > Event Log Service > Security > Maximum log file size | 512000 KB | Default size overwrites evidence within hours on a busy host |

## Verification

```
gpupdate /force
gpresult /r /scope computer
auditpol /get /category:*
```

Output from WS01: [evidence/ws01-gpresult-auditpol.txt](evidence/ws01-gpresult-auditpol.txt)
