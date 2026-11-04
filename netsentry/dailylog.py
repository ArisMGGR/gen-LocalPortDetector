"""Human-readable log with one file per local day, such as 2026-11-04.log."""
from __future__ import annotations

import logging
import os
import re
import time
from typing import Optional

log = logging.getLogger(__name__)

DAY_FILE = re.compile(r"\d{4}-\d{2}-\d{2}\.log")


class DailyLog:
    def __init__(self, directory: str):
        self.directory = directory

    def write(self, level: str, message: str, now: Optional[float] = None) -> None:
        if not self.directory:
            return
        stamp = time.localtime(time.time() if now is None else now)
        # Hostnames come from reverse DNS, so a line break in one must not forge a log line.
        line = " ".join(message.splitlines())
        try:
            os.makedirs(self.directory, exist_ok=True)
            with open(self._path(stamp), "a", encoding="utf-8") as fh:
                fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S', stamp)} [{level}] {line}\n")
        except OSError as exc:
            log.error("cannot write daily log: %s", exc)

    def prune(self, older_than: float) -> int:
        """Delete day files from before *older_than*; anything else in the folder is left alone."""
        if not self.directory:
            return 0
        cutoff = time.strftime("%Y-%m-%d", time.localtime(older_than))
        removed = 0
        try:
            for name in os.listdir(self.directory):
                if DAY_FILE.fullmatch(name) and name[:10] < cutoff:
                    os.unlink(os.path.join(self.directory, name))
                    removed += 1
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.error("cannot prune daily logs: %s", exc)
        return removed

    def _path(self, stamp: time.struct_time) -> str:
        return os.path.join(self.directory, time.strftime("%Y-%m-%d", stamp) + ".log")
