#!/usr/bin/env bash
#
# ssh-log-analyzer.sh - summarise SSH authentication activity from auth.log
#
# Reports:
#   - totals: failed passwords, invalid-user attempts, successful logins
#   - failed attempts per source IP, flagging IPs at or above a threshold
#   - usernames tried that do not exist on the host
#   - successful logins (user, source IP, method)
#   - [!] successful logins from an IP that had failed attempts first
#   - sudo commands run, per user
#
# Usage:
#   sudo ./ssh-log-analyzer.sh [-f logfile] [-t threshold] [-n top] [-o outdir]
#
#   -f  log file to read            (default: /var/log/auth.log)
#   -t  failures per IP to flag     (default: 5)
#   -n  rows to show in top lists   (default: 10)
#   -o  directory for the report    (default: ~/reports)
#
set -euo pipefail

LOG_FILE="/var/log/auth.log"
THRESHOLD=5
TOP=10
OUT_DIR="${SUDO_USER:+/home/$SUDO_USER}/reports"
[[ -z "${SUDO_USER:-}" ]] && OUT_DIR="$HOME/reports"

usage() {
    sed -n '/^# Usage:/,/^# *-o/p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts ":f:t:n:o:h" opt; do
    case "$opt" in
        f) LOG_FILE="$OPTARG" ;;
        t) THRESHOLD="$OPTARG" ;;
        n) TOP="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        :) echo "Option -$OPTARG needs a value" >&2; exit 1 ;;
        \?) echo "Unknown option -$OPTARG" >&2; usage; exit 1 ;;
    esac
done

[[ -r "$LOG_FILE" ]] || { echo "Cannot read $LOG_FILE (run with sudo?)" >&2; exit 1; }
[[ "$THRESHOLD" =~ ^[0-9]+$ && "$TOP" =~ ^[0-9]+$ ]] || { echo "-t and -n must be numbers" >&2; exit 1; }

mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/ssh-report_$(date +%Y%m%d_%H%M%S).txt"

# --- Normalise sshd lines into: TYPE USER IP TIMESTAMP [METHOD] -----------
# Works with both log formats:
#   2026-11-11T13:32:53.07+00:00 ubu01 sshd-session[1707]: Failed password ...
#   Nov 11 13:32:53 ubu01 sshd[1707]: Failed password ...
EVENTS=$(grep -E 'sshd(-session)?\[[0-9]+\]:' "$LOG_FILE" | awk '
{
    ts = ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? $1 : $1 " " $2 " " $3
    user = ""; ip = ""
    for (i = 1; i <= NF; i++) if ($i == "from") { ip = $(i + 1); break }
}
/Failed password for/ {
    for (i = 1; i <= NF; i++)
        if ($i == "for") { user = ($(i + 1) == "invalid") ? $(i + 3) : $(i + 1); break }
    print "FAIL", user, ip, ts
    next
}
/Accepted / {
    for (i = 1; i <= NF; i++)
        if ($i == "Accepted") { method = $(i + 1); user = $(i + 3); break }
    print "OK", user, ip, ts, method
    next
}
/Invalid user / {
    for (i = 1; i <= NF; i++) if ($i == "user") { user = $(i + 1); break }
    if (user == "from") user = "(empty)"
    print "INVALID", user, ip, ts
}' || true)

count() { awk -v t="$1" '$1 == t' <<< "$EVENTS" | grep -c . || true; }

FAILED=$(count FAIL)
INVALID=$(count INVALID)
SUCCESS=$(count OK)

{
    echo "=================================================="
    echo " SSH Log Analysis - $(hostname)"
    echo " Source : $LOG_FILE"
    echo " Run at : $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo " Brute-force threshold: $THRESHOLD failures per IP"
    echo "=================================================="
    echo
    echo "## Summary"
    printf "  %-28s %s\n" "Failed password attempts:" "$FAILED"
    printf "  %-28s %s\n" "Invalid-user attempts:" "$INVALID"
    printf "  %-28s %s\n" "Successful logins:" "$SUCCESS"
    echo

    echo "## Failed attempts by source IP (top $TOP)"
    if [[ "$FAILED" -eq 0 ]]; then
        echo "  none"
    else
        awk '$1 == "FAIL" { print $3 }' <<< "$EVENTS" | sort | uniq -c | sort -rn | head -n "$TOP" |
        awk -v t="$THRESHOLD" '{
            flag = ($1 >= t) ? "  [!] POSSIBLE BRUTE FORCE" : ""
            printf "  %6d  %-18s%s\n", $1, $2, flag
        }'
    fi
    echo

    echo "## Usernames tried that do not exist (top $TOP)"
    if [[ "$INVALID" -eq 0 ]]; then
        echo "  none"
    else
        awk '$1 == "INVALID" { print $2 }' <<< "$EVENTS" | sort | uniq -c | sort -rn | head -n "$TOP" |
        awk '{ printf "  %6d  %s\n", $1, $2 }'
    fi
    echo

    echo "## Successful logins"
    if [[ "$SUCCESS" -eq 0 ]]; then
        echo "  none"
    else
        awk '$1 == "OK" { printf "  %-34s %-12s from %-16s (%s)\n", $4, $2, $3, $5 }' <<< "$EVENTS"
    fi
    echo

    echo "## [!] Successful login after failed attempts from the same IP"
    SUSPECT=$(awk '
        $1 == "FAIL" { fails[$3]++ }
        $1 == "OK" && fails[$3] > 0 {
            printf "  %-34s %-12s from %-16s after %d failed attempt(s)\n", $4, $2, $3, fails[$3]
            fails[$3] = 0
        }' <<< "$EVENTS")
    if [[ -z "$SUSPECT" ]]; then echo "  none"; else echo "$SUSPECT"; fi
    echo

    echo "## sudo commands by user"
    SUDO=$(grep -E 'sudo(\[[0-9]+\])?: +[^ ]+ : .*COMMAND=' "$LOG_FILE" |
           sed -E 's/.*sudo(\[[0-9]+\])?: +([^ ]+) : .*/\2/' | sort | uniq -c | sort -rn || true)
    if [[ -z "$SUDO" ]]; then echo "  none"; else awk '{ printf "  %6d  %s\n", $1, $2 }' <<< "$SUDO"; fi
    echo
} | tee "$REPORT"

[[ -n "${SUDO_USER:-}" ]] && chown -R "$SUDO_USER:" "$OUT_DIR" 2>/dev/null || true
echo "Report saved to: $REPORT"
