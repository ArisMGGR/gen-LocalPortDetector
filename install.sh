#!/usr/bin/env bash
# Install or upgrade netsentry as a systemd service. Run as root: sudo ./install.sh
set -euo pipefail

PREFIX=/opt/netsentry
CONF_DIR=/etc/netsentry
UNIT=/etc/systemd/system/netsentry.service
BIN=/usr/local/bin/netsentry
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SRC/logs"
OLD_LOG_DIR=/var/log/netsentry/logs
DROPIN_DIR=/etc/systemd/system/netsentry.service.d

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

# -I keeps the current directory (and PYTHONPATH) off sys.path, so root never imports code from where it runs.
cat > "$BIN" <<EOF
#!/bin/sh
exec python3 -I -c 'import sys; sys.path.insert(0, "$PREFIX"); from netsentry.cli import main; sys.exit(main())' "\$@"
EOF
chmod 0755 "$BIN"

install -d -m 0750 -o root -g netsentry "$CONF_DIR"
if [[ -f "$CONF_DIR/netsentry.conf" ]]; then
    echo "Keeping existing $CONF_DIR/netsentry.conf"
else
    install -m 0640 -o root -g netsentry "$SRC/packaging/netsentry.conf" "$CONF_DIR/netsentry.conf"
    echo "Installed default config to $CONF_DIR/netsentry.conf"
fi

# Daily logs go to <project>/logs. The folder belongs to the service user, with your group so
# you can read the logs without sudo (setgid makes new files inherit that group).
BAD_PATH_CHARS='[[:space:]|&\\]'
[[ ! "$LOG_DIR" =~ $BAD_PATH_CHARS ]] || die "the project path must not contain spaces, |, & or \\: $SRC"
LOG_GROUP="$(id -gn "${SUDO_USER:-root}")"
install -d -o netsentry -g "$LOG_GROUP" "$LOG_DIR"
chown netsentry:"$LOG_GROUP" "$LOG_DIR"
chmod 2750 "$LOG_DIR"
# Bring over the day files written to the old location, keeping any that already exist here.
if compgen -G "$OLD_LOG_DIR/????-??-??.log" >/dev/null; then
    cp -n --preserve=timestamps "$OLD_LOG_DIR"/????-??-??.log "$LOG_DIR"/
    chown netsentry:"$LOG_GROUP" "$LOG_DIR"/*.log
    chmod 0640 "$LOG_DIR"/*.log
fi

CONF="$CONF_DIR/netsentry.conf"
if grep -qE '^[[:space:]]*daily_log_dir[[:space:]]*=' "$CONF"; then
    sed -i -E "s|^[[:space:]]*daily_log_dir[[:space:]]*=.*|daily_log_dir = $LOG_DIR|" "$CONF"
elif grep -qE '^\[storage\]' "$CONF"; then
    sed -i "/^\[storage\]/a daily_log_dir = $LOG_DIR" "$CONF"
else
    printf '\n[storage]\ndaily_log_dir = %s\n' "$LOG_DIR" >> "$CONF"
fi
echo "Daily logs go to $LOG_DIR"

# The unit's ProtectHome=yes hides all of /home from the service. This drop-in swaps it for an
# empty /home and bind-mounts only the logs folder back in, so nothing else in /home is visible.
install -d -m 0755 "$DROPIN_DIR"
cat > "$DROPIN_DIR/logs.conf" <<EOF
# Written by install.sh: lets the service write its daily logs to the project folder.
[Service]
ProtectHome=tmpfs
BindPaths=$LOG_DIR
EOF
chmod 0644 "$DROPIN_DIR/logs.conf"

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
