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
        self.last_write = time.monotonic()  # when the last line was attempted, for the "No logs" heartbeat

    def idle_for(self) -> float:
        return time.monotonic() - self.last_write

    def write(self, level: str, message: str, now: Optional[float] = None) -> None:
        if not self.directory:
            return
        self.last_write = time.monotonic()
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


class DailyLogHandler(logging.Handler):
    """Copies the program's own log output (startup, errors, failed notifications...) into the daily log."""

    def __init__(self, daily_log: DailyLog):
        super().__init__()
        self.daily_log = daily_log

    def emit(self, record: logging.LogRecord) -> None:
        # Our own write failures must not loop back in; records marked skip_daily are written separately.
        if record.name == __name__ or getattr(record, "skip_daily", False):
            return
        try:
            message = record.getMessage()
            if record.exc_info and record.exc_info[1] is not None:
                message += f": {record.exc_info[1]}"  # the traceback itself stays in the journal
            self.daily_log.write(record.levelname, message, record.created)
        except Exception:
            self.handleError(record)
