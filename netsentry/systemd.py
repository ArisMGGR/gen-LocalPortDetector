"""Minimal systemd integration: sd_notify and journald-aware logging."""
from __future__ import annotations

import logging
import os
import socket
import sys

_PRIORITIES = {logging.DEBUG: 7, logging.INFO: 6, logging.WARNING: 4, logging.ERROR: 3, logging.CRITICAL: 2}


def sd_notify(state: str) -> None:
    """Send a state such as READY=1 or WATCHDOG=1 to systemd; a no-op outside a Type=notify unit."""
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(state.encode())
    except OSError:
        pass


class JournalFormatter(logging.Formatter):
    """Prefixes each line with <N> so journald stores it with the matching priority."""

    def format(self, record: logging.LogRecord) -> str:
        return f"<{_PRIORITIES.get(record.levelno, 6)}>{super().format(record)}"


def setup_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if os.environ.get("JOURNAL_STREAM"):
        handler.setFormatter(JournalFormatter("%(message)s"))  # journald adds its own timestamps
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=level, handlers=[handler])
