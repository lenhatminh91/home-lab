# Incident report: SSH brute force against UBU01

| Field | Value |
|---|---|
| Date | 2026-11-11 |
| Detected by | `ssh-log-analyzer.sh` (threshold 5 failures per source IP) |
| Target | UBU01, 10.10.10.30, OpenSSH |
| Source | 10.10.10.10 (DC01) |
| Severity | Medium: brute force without successful login, but from an unexpected source |
| Status | Simulated exercise, closed |

## Summary

Between about 21:09 and 21:11 (UTC+7), host 10.10.10.10 made repeated SSH password attempts against UBU01 using common default usernames. The analyzer flagged the source as **POSSIBLE BRUTE FORCE**. No successful login from 10.10.10.10 was recorded.

## Evidence

From `/var/log/auth.log`, summarised by the analyzer:

- 9+ `Failed password` entries from 10.10.10.10
- `Invalid user` entries for `admin`, `test`, `oracle`; attempts against `root`, which exists but cannot log in with a password over SSH
- No `Accepted ...` entry from 10.10.10.10

Screenshot: [21-ssh-analyzer-brute-force-from-dc01.png](../screenshots/21-ssh-analyzer-brute-force-from-dc01.png)

## Analysis

- The usernames match generic wordlists used by internet bots, not real accounts on the host, which points to automated guessing rather than a user mistyping.
- **The source is the domain controller.** A DC has no business reason to open SSH sessions to Linux servers. In a real environment this would raise the priority: the question is no longer only "is UBU01 safe" but "is DC01 compromised and being used to move laterally".

## Related false positive

The same report flagged 10.10.10.1 (the admin's laptop) for 10 failures followed by a successful login. Investigation showed a mistyped username (`ladadmin`) and one mistyped password by the legitimate administrator, followed by a correct login. Classified as a false positive. This led to tuning the rule so the failure count resets after each successful login.

## Recommended actions (real environment)

1. Block 10.10.10.10 at the host firewall (`ufw deny from 10.10.10.10 to any port 22`) while investigating.
2. Investigate DC01: logon events (4624) and process creation (4688) around 21:09 for who launched `ssh.exe`.
3. Harden SSH on UBU01: key-based authentication only, `PermitRootLogin no`, and `fail2ban` to block repeated failures automatically.
4. Forward `auth.log` to a SIEM so this alert fires in real time instead of on a manual script run (Project 4).

## Lab note

In this exercise the "attacker" was the lab owner running `ssh admin@10.10.10.30` from DC01 to generate test data.
