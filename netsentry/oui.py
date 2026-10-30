"""MAC vendor (OUI) lookup using the vendor databases Linux distros commonly ship."""
from __future__ import annotations

import os
import re
from typing import Dict, Optional

from .netutil import is_randomized_mac

CANDIDATE_FILES = (
    "/usr/share/ieee-data/oui.txt",        # ieee-data package
    "/usr/share/arp-scan/ieee-oui.txt",    # arp-scan
    "/usr/share/nmap/nmap-mac-prefixes",   # nmap
    "/usr/share/wireshark/manuf",          # wireshark
)
_LINE_RE = re.compile(
    r"^([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})[-:]?([0-9A-Fa-f]{2})\s+(?:\((?:hex|base 16)\)\s+)?(.+)$")


def parse_oui_file(path: str) -> Dict[str, str]:
    table: Dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            match = _LINE_RE.match(line.strip())
            if match:
                prefix = "".join(match.group(1, 2, 3)).upper()
                table.setdefault(prefix, match.group(4).split("\t")[-1].strip())
    return table


class OuiDB:
    def __init__(self, path: str = ""):
        self.path = path
        self._table: Optional[Dict[str, str]] = None

    def lookup(self, mac: str) -> str:
        if is_randomized_mac(mac):
            return "randomized MAC"
        if self._table is None:
            self._table = self._load()
        return self._table.get(mac.replace(":", "")[:6].upper(), "")

    def _load(self) -> Dict[str, str]:
        for path in ([self.path] if self.path else CANDIDATE_FILES):
            if os.path.isfile(path):
                try:
                    return parse_oui_file(path)
                except OSError:
                    continue
        return {}
