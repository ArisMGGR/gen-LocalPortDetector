#!/usr/bin/env bash
# Install or upgrade netsentry as a systemd service. Run as root: sudo ./install.sh
set -euo pipefail

PREFIX=/opt/netsentry
CONF_DIR=/etc/netsentry
UNIT=/etc/systemd/system/netsentry.service
BIN=/usr/local/bin/netsentry
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root: sudo $0"
command -v systemctl >/dev/null || die "systemd is required"
command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "Python 3.8 or newer is required"
python3 -c 'import sqlite3; assert sqlite3.sqlite_version_info >= (3, 24)' \
    || die "SQLite 3.24 or newer is required"

if ! id netsentry >/dev/null 2>&1; then
    echo "Creating system user 'netsentry'"
    useradd --system --no-create-home --home-dir /var/lib/netsentry \
        --shell "$(command -v nologin || echo /bin/false)" netsentry
fi

echo "Installing program to $PREFIX"
install -d -m 0755 "$PREFIX"
rm -rf "$PREFIX/netsentry"
cp -r "$SRC/netsentry" "$PREFIX/"
find "$PREFIX" -name __pycache__ -prune -exec rm -rf {} +
install -m 0644 "$SRC/README.md" "$PREFIX/README.md"
chmod -R u=rwX,go=rX "$PREFIX"

cat > "$BIN" <<EOF
#!/bin/sh
PYTHONPATH=$PREFIX exec python3 -m netsentry "\$@"
EOF
chmod 0755 "$BIN"

install -d -m 0750 -o root -g netsentry "$CONF_DIR"
if [[ -f "$CONF_DIR/netsentry.conf" ]]; then
    echo "Keeping existing $CONF_DIR/netsentry.conf"
else
    install -m 0640 -o root -g netsentry "$SRC/packaging/netsentry.conf" "$CONF_DIR/netsentry.conf"
    echo "Installed default config to $CONF_DIR/netsentry.conf"
fi

install -m 0644 "$SRC/packaging/netsentry.service" "$UNIT"
systemctl daemon-reload

if systemctl is-active --quiet netsentry; then
    systemctl restart netsentry
    echo "netsentry upgraded and restarted."
elif [[ -z "${NETSENTRY_SKIP_NEXT_STEPS:-}" ]]; then
    cat <<EOF

netsentry is installed. Configure notifications and start it with:
  sudo netsentry setup

Or by hand: edit $CONF_DIR/netsentry.conf, then run
  sudo netsentry test-notify && sudo systemctl enable --now netsentry
EOF
fi
