#!/bin/bash
# Runs sandbox-probe.py in a transient unit with the installed unit's [Service] settings. Run as root.
set -euo pipefail

# systemd-run rejects BindLogSockets before 257, where the unit ignores it.
version=$(systemctl --version | awk 'NR == 1 { print $2 }')
args=()
while IFS= read -r line; do
    args+=(-p "$line")
done < <(systemctl cat ssh-kex-tarpit.service | awk -v version="$version" '
    /^\[/ { s = ($0 == "[Service]"); next }
    s && /^[A-Za-z]+=/ && !/^(ExecStart|Restart|RestartSec)=/ && !(version < 257 && /^BindLogSockets=/)')

exec systemd-run --quiet --pipe --wait --collect "${args[@]}" /usr/bin/python3 -I - < "$(dirname "$0")/sandbox-probe.py"
