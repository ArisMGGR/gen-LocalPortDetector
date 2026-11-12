"""The long-running monitoring loop that the systemd service executes."""
from __future__ import annotations

import json
import logging
import signal
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List

from .config import Config
from .dailylog import DailyLog, DailyLogHandler
from .monitor import Monitor
from .netutil import arp_scan, resolve_hostnames, resolve_interface
from .notify import Notifier
from .oui import OuiDB
from .store import Event, Store
from .systemd import sd_notify

log = logging.getLogger(__name__)

EX_CONFIG = 78          # the unit sets RestartPreventExitStatus=78 so this doesn't restart-loop
WATCHDOG_PING = 15      # seconds between watchdog pings while idle
EVENT_LOG_LEVELS = {"info": logging.INFO, "warning": logging.WARNING, "critical": logging.CRITICAL}


class Daemon:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.stopping = threading.Event()
        self.store = Store(cfg.storage.database)
        resolver = resolve_hostnames if cfg.scan.resolve_hostnames else None
        self.monitor = Monitor(self.store, cfg.detection, OuiDB(cfg.storage.oui_file), resolver)
        self.notifier = Notifier(cfg)
        self.daily_log = DailyLog(cfg.storage.daily_log_dir)
        self._log_handler = DailyLogHandler(self.daily_log)
        logging.getLogger(__package__).addHandler(self._log_handler)
        self._last_prune = 0.0
        self._next_check = time.monotonic() + cfg.storage.daily_log_check

    def close(self) -> None:
        logging.getLogger(__package__).removeHandler(self._log_handler)
        self.store.close()

    def run(self) -> int:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self.stopping.set())
        log.info("netsentry started: scanning every %ss, %d notification channel(s)",
                 self.cfg.scan.interval, len(self.notifier.channels))
        if not self.notifier.channels:
            log.warning("no notification channels configured; alerts will only be logged")
        sd_notify("READY=1")
        try:
            while not self.stopping.is_set():
                started = time.monotonic()
                try:
                    self.cycle()
                    self._daily_check()
                except PermissionError as exc:
                    log.critical("%s: raw sockets need root or CAP_NET_RAW; run through the systemd unit or with sudo",
                                 exc)
                    return EX_CONFIG
                except RuntimeError as exc:  # e.g. no IPv4 address yet while the network comes up
                    log.error("scan skipped: %s", exc)
                except Exception:
                    log.exception("scan cycle failed")
                self._sleep(self.cfg.scan.interval - (time.monotonic() - started))
        finally:
            sd_notify("STOPPING=1")
            log.info("netsentry stopped")
            self.close()
        return 0

    def cycle(self) -> None:
        scan_cfg = self.cfg.scan
        iface = resolve_interface(scan_cfg.interface, scan_cfg.subnet)
        scan = arp_scan(iface, scan_cfg.timeout, scan_cfg.passes, scan_cfg.max_hosts)
        events = self.monitor.process(scan)
        online = len(scan.by_mac())
        log.debug("scanned %s on %s: %d devices online, %d events", iface.network, iface.name, online, len(events))
        for event in events:
            # skip_daily: _daily_events writes these with the event's own time, whatever the log level
            log.log(EVENT_LOG_LEVELS[event.severity], "%s: %s", event.kind, event.message,
                    extra={"skip_daily": True})
        self._append_event_log(events)
        self._daily_events(events)
        self.notifier.send(events)
        self._prune()
        sd_notify(f"STATUS={online} devices online on {iface.network} (last scan {time.strftime('%H:%M:%S')})")

    def _append_event_log(self, events: List[Event]) -> None:
        """JSON-lines copy of every event, handy for grep, logrotate or shipping to a SIEM."""
        if not events or not self.cfg.storage.event_log:
            return
        try:
            with open(self.cfg.storage.event_log, "a", encoding="utf-8") as fh:
                for e in events:
                    record = {"time": datetime.fromtimestamp(e.ts, timezone.utc).isoformat(), **asdict(e)}
                    fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            log.error("cannot write event log: %s", exc)

    def _daily_events(self, events: List[Event]) -> None:
        for e in events:
            self.daily_log.write(e.severity.upper(), f"{e.kind}: {e.message}", e.ts)

    def _daily_check(self) -> None:
        """Periodic reminder of unapproved devices still online, and a heartbeat when the log has been silent."""
        interval = self.cfg.storage.daily_log_check
        if time.monotonic() >= self._next_check:
            self._next_check = time.monotonic() + interval
            for d in self.store.devices(unapproved_only=True):
                if d.online:
                    self.daily_log.write("WARNING", f"Unapproved device online: {d.describe()}")
        if self.daily_log.idle_for() >= interval:
            self.daily_log.write("INFO", "No logs")

    def _prune(self) -> None:
        now = time.time()
        if now - self._last_prune < 86400:
            return
        self._last_prune = now
        cutoff = now - self.cfg.storage.keep_events_days * 86400
        removed = self.store.prune_events(cutoff) + self.daily_log.prune(cutoff)
        if removed:
            log.info("pruned %d old events and daily logs", removed)

    def _sleep(self, seconds: float) -> None:
        deadline = time.monotonic() + max(0.0, seconds)
        while not self.stopping.is_set():
            sd_notify("WATCHDOG=1")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self.stopping.wait(min(remaining, WATCHDOG_PING))
