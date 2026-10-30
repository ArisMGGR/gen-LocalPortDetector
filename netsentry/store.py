"""SQLite persistence for known devices, events and small pieces of state."""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass, field
from typing import List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ips        TEXT NOT NULL DEFAULT '',
    hostname   TEXT NOT NULL DEFAULT '',
    vendor     TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    approved   INTEGER NOT NULL DEFAULT 0,
    online     INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    mac      TEXT NOT NULL DEFAULT '',
    ip       TEXT NOT NULL DEFAULT '',
    message  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass
class Device:
    mac: str
    ips: List[str] = field(default_factory=list)
    hostname: str = ""
    vendor: str = ""
    name: str = ""
    approved: bool = False
    online: bool = True
    first_seen: float = 0.0
    last_seen: float = 0.0

    def label(self) -> str:
        return self.name or self.hostname or self.vendor or "unknown device"

    def describe(self) -> str:
        details = [d for d in (self.name, self.hostname, self.vendor) if d]
        text = f"{self.mac} at {', '.join(self.ips) or 'no IP'}"
        return f"{text} ({'; '.join(details)})" if details else text


@dataclass
class Event:
    kind: str
    severity: str
    message: str
    mac: str = ""
    ip: str = ""
    ts: float = field(default_factory=time.time)


class Store:
    def __init__(self, path: str):
        # The default rollback journal (not WAL) keeps no root-owned side files behind when the
        # CLI runs as root against the service's database.
        self.db = sqlite3.connect(path, timeout=15)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.db.close()

    def commit(self) -> None:
        self.db.commit()

    def get(self, mac: str) -> Optional[Device]:
        row = self.db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return _device(row) if row else None

    def devices(self, unapproved_only: bool = False) -> List[Device]:
        where = " WHERE approved = 0" if unapproved_only else ""
        rows = self.db.execute(f"SELECT * FROM devices{where} ORDER BY approved, online DESC, last_seen DESC")
        return [_device(row) for row in rows]

    def save(self, d: Device) -> None:
        """Insert or update a device. Name and approval are only ever changed through the CLI."""
        self.db.execute(
            """INSERT INTO devices (mac, ips, hostname, vendor, name, approved, online, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (mac) DO UPDATE SET ips = excluded.ips, hostname = excluded.hostname,
                   vendor = excluded.vendor, online = excluded.online, last_seen = excluded.last_seen""",
            (d.mac, ",".join(d.ips), d.hostname, d.vendor, d.name, int(d.approved), int(d.online),
             d.first_seen, d.last_seen))

    def set_approved(self, mac: str, approved: bool, name: Optional[str] = None) -> bool:
        if name is None:
            cur = self.db.execute("UPDATE devices SET approved = ? WHERE mac = ?", (int(approved), mac))
        else:
            cur = self.db.execute("UPDATE devices SET approved = ?, name = ? WHERE mac = ?",
                                  (int(approved), name, mac))
        self.db.commit()
        return cur.rowcount > 0

    def approve_all(self) -> int:
        cur = self.db.execute("UPDATE devices SET approved = 1 WHERE approved = 0")
        self.db.commit()
        return cur.rowcount

    def forget(self, mac: str) -> bool:
        cur = self.db.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        self.db.commit()
        return cur.rowcount > 0

    def add_event(self, e: Event) -> None:
        self.db.execute("INSERT INTO events (ts, kind, severity, mac, ip, message) VALUES (?, ?, ?, ?, ?, ?)",
                        (e.ts, e.kind, e.severity, e.mac, e.ip, e.message))

    def events(self, limit: int = 50) -> List[Event]:
        rows = self.db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [Event(r["kind"], r["severity"], r["message"], r["mac"], r["ip"], r["ts"]) for r in reversed(rows)]

    def prune_events(self, older_than: float) -> int:
        cur = self.db.execute("DELETE FROM events WHERE ts < ?", (older_than,))
        self.db.commit()
        return cur.rowcount

    def meta_get(self, key: str) -> Optional[str]:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def meta_set(self, key: str, value: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))


def _device(row: sqlite3.Row) -> Device:
    return Device(mac=row["mac"], ips=[ip for ip in row["ips"].split(",") if ip], hostname=row["hostname"],
                  vendor=row["vendor"], name=row["name"], approved=bool(row["approved"]),
                  online=bool(row["online"]), first_seen=row["first_seen"], last_seen=row["last_seen"])
