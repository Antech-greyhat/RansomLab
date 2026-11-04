#!/usr/bin/env bash
# Read-only observations. This does not configure a network or arm a scenario.
set -euo pipefail

python_command=''
if command -v python3 >/dev/null 2>&1; then
    python_command='python3'
elif command -v python >/dev/null 2>&1; then
    python_command='python'
fi

if [[ -z "$python_command" ]]; then
    printf '%s\n' 'RansomLab preflight: Python is unavailable; nothing was installed.'
    exit 2
fi
if ! python_version=$("$python_command" --version 2>/dev/null); then
    printf '%s\n' 'RansomLab preflight: the Python version command failed.'
    exit 2
fi

vmware_indicator='unverified'
if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
    IFS= read -r manufacturer < /sys/class/dmi/id/sys_vendor || true
    case "${manufacturer:-}" in
        *[Vv][Mm][Ww][Aa][Rr][Ee]*) vmware_indicator='present' ;;
        *) vmware_indicator='not observed' ;;
    esac
fi

elevation='non-root'
if [[ "$EUID" -eq 0 ]]; then elevation='root: use a dedicated non-root lab account'; fi

printf 'RansomLab read-only preflight\nPython: %s\nVMware indicator: %s\nAccount: %s\n' \
    "$python_version" "$vmware_indicator" "$elevation"
printf '%s\n' \
    'Snapshot and network isolation: not verified by this script.' \
    'Role: compose fixed-action scenario data and analyse reviewed synthetic exports.' \
    'Use an approved isolated guest network; do not enable NAT, bridging or host shares.' \
    'Review the manual transfer procedure and record a clean snapshot before the exercise.' \
    'No scan, SSH command, package installation or host configuration was performed.' \
    'A successful script exit is not approval to execute fixture impact.'
