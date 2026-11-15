#!/usr/bin/env bash
# Remove netsentry. Config, device database and logs are kept unless --purge is given.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "error: run as root: sudo $0 [--purge]" >&2; exit 1; }

systemctl disable --now netsentry 2>/dev/null || true
rm -f /etc/systemd/system/netsentry.service /usr/local/bin/netsentry
rm -rf /etc/systemd/system/netsentry.service.d
rm -rf /opt/netsentry
systemctl daemon-reload

if [[ "${1:-}" == "--purge" ]]; then
    rm -rf /etc/netsentry /var/lib/netsentry /var/log/netsentry
    userdel netsentry 2>/dev/null || true
    echo "netsentry removed, including config, data and logs (the project's logs folder is left alone)."
else
    echo "netsentry removed. Kept /etc/netsentry, /var/lib/netsentry and /var/log/netsentry (use --purge to delete)."
fi
