# Lab credentials (template)

Real passwords are **not** committed. Keep your own copy outside the repository; `.gitignore` excludes `credentials.md` and `*credentials*.txt`.

| Host | Account | Password |
|---|---|---|
| DC01 | `LAB\Administrator` | `<your-domain-admin-password>` |
| DC01 | DSRM (directory restore) | `<your-dsrm-password>` |
| WS01 | local admin | `<your-local-password>` |
| Domain users | `LAB\<firstname>.<lastname>` | initial password set at run time by `New-LabUsers.ps1` |
| UBU01 | `labadmin` | `<your-ubuntu-password>` |

Passwords must meet the domain policy: at least 12 characters with upper case, lower case, digits and symbols.
