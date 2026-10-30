"""Turns scan results into device state changes and security events."""
from __future__ import annotations

import time
from typing import Callable, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .config import DetectionConfig
from .netutil import ScanResult, is_randomized_mac
from .oui import OuiDB
from .store import Device, Event, Store

Resolver = Callable[[Iterable[str]], Dict[str, str]]


class Monitor:
    def __init__(self, store: Store, cfg: DetectionConfig, oui: OuiDB, resolver: Optional[Resolver] = None):
        self.store = store
        self.cfg = cfg
        self.oui = oui
        self.resolver = resolver
        self._reported_conflicts: Set[Tuple[str, FrozenSet[str]]] = set()

    def process(self, scan: ScanResult, now: Optional[float] = None) -> List[Event]:
        """Record one scan and return the events it produced (also saved to the store)."""
        now = time.time() if now is None else now
        baseline = self.cfg.baseline_on_first_run and self.store.meta_get("baseline_done") is None
        seen = scan.by_mac()
        events: List[Event] = []

        unknown = {mac: ips for mac, ips in seen.items() if self.store.get(mac) is None}
        names = self.resolver(ips[0] for ips in unknown.values()) if self.resolver and unknown else {}

        for mac, ips in seen.items():
            device = self.store.get(mac)
            if device is None:
                device = Device(mac=mac, ips=ips, hostname=names.get(ips[0], ""), vendor=self.oui.lookup(mac),
                                approved=baseline, first_seen=now, last_seen=now)
                if not baseline:
                    events.append(self._new_device_event(device, now))
            else:
                events.extend(self._update_known(device, ips, now))
            self.store.save(device)

        events.extend(self._mark_offline(seen, now))
        events.extend(self._check_conflicts(scan, now))
        events.extend(self._check_gateway(scan, now))

        if baseline:
            self.store.meta_set("baseline_done", str(now))
            events.append(Event("baseline", "warning",
                                f"Monitoring started. The {len(seen)} devices currently on {scan.interface.network} "
                                "were recorded as trusted; review them with 'netsentry list'.", ts=now))
        for event in events:
            self.store.add_event(event)
        self.store.commit()
        return events

    def _new_device_event(self, d: Device, now: float) -> Event:
        message = f"New device joined the network: {d.describe()}"
        if is_randomized_mac(d.mac):
            message += (". It uses a randomized MAC: often a phone or laptop privacy feature, "
                        "but it also hides who made the device")
        return Event("new_device", "warning", message, d.mac, d.ips[0], now)

    def _update_known(self, d: Device, ips: List[str], now: float) -> List[Event]:
        events = []
        old_ips, was_online = d.ips, d.online
        d.ips, d.online, d.last_seen = ips, True, now
        if not was_online:
            if not d.approved and self.cfg.alert_on_unknown_return:
                events.append(Event("unapproved_return", "warning",
                                    f"Unapproved device is back online: {d.describe()}", d.mac, ips[0], now))
            else:
                events.append(Event("online", "info", f"Device back online: {d.describe()}", d.mac, ips[0], now))
        if old_ips and set(old_ips) != set(ips):
            events.append(Event("ip_change", "info",
                                f"{d.label()} ({d.mac}) changed IP: {', '.join(old_ips)} -> {', '.join(ips)}",
                                d.mac, ips[0], now))
        return events

    def _mark_offline(self, seen: Dict[str, List[str]], now: float) -> List[Event]:
        events = []
        for d in self.store.devices():
            if d.online and d.mac not in seen and now - d.last_seen >= self.cfg.offline_after:
                d.online = False
                self.store.save(d)
                events.append(Event("offline", "info", f"Device went offline: {d.describe()}",
                                    d.mac, d.ips[0] if d.ips else "", now))
        return events

    def _check_conflicts(self, scan: ScanResult, now: float) -> List[Event]:
        """Alert once per distinct conflict while it lasts, not on every scan."""
        if not self.cfg.conflict_alerts:
            return []
        current = {(ip, frozenset(macs)) for ip, macs in scan.conflicts().items()}
        events = [Event("ip_conflict", "critical",
                        f"IP {ip} is being claimed by several MACs ({', '.join(sorted(macs))}): "
                        "possible ARP spoofing or an IP address conflict", ip=ip, ts=now)
                  for ip, macs in sorted(current - self._reported_conflicts, key=lambda c: c[0])]
        self._reported_conflicts = current
        return events

    def _check_gateway(self, scan: ScanResult, now: float) -> List[Event]:
        gateway = scan.interface.gateway
        if not self.cfg.watch_gateway or not gateway:
            return []
        macs = scan.claims.get(gateway, set())
        if len(macs) != 1:
            return []  # gateway didn't answer, or a conflict that _check_conflicts reports
        mac = next(iter(macs))
        key = f"gateway_mac:{gateway}"
        previous = self.store.meta_get(key)
        self.store.meta_set(key, mac)
        if previous and previous != mac:
            return [Event("gateway_change", "critical",
                          f"The MAC address of gateway {gateway} changed from {previous} to {mac}. Unless you "
                          "replaced your router, this is a strong sign of ARP spoofing (man-in-the-middle).",
                          mac, gateway, now)]
        return []
