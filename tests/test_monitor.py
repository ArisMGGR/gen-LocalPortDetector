import ipaddress
import unittest
from unittest import mock

from netsentry.config import DetectionConfig
from netsentry.monitor import Monitor
from netsentry.netutil import Interface, ScanResult
from netsentry.oui import OuiDB
from netsentry.store import Store

SELF = "02:00:00:00:00:01"
ROUTER = "00:11:22:33:44:55"
LAPTOP = "00:aa:bb:cc:dd:01"
STRANGER = "00:de:ad:be:ef:01"
ATTACKER = "00:66:66:66:66:66"


def scan(*claims):
    iface = Interface("eth0", SELF, "192.168.1.2", ipaddress.IPv4Network("192.168.1.0/24"), "192.168.1.1")
    result = ScanResult(iface)
    result.add("192.168.1.2", SELF)
    for ip, mac in claims:
        result.add(ip, mac)
    return result


def kinds(events):
    return [e.kind for e in events]


class MonitorTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.cfg = DetectionConfig(offline_after=300)
        self.monitor = Monitor(self.store, self.cfg, OuiDB("/nonexistent"),
                               resolver=lambda ips: {ip: "host-" + ip.split(".")[-1] for ip in ips})
        self.home = [("192.168.1.1", ROUTER), ("192.168.1.20", LAPTOP)]

    def test_first_scan_creates_baseline_without_device_alerts(self):
        events = self.monitor.process(scan(*self.home), now=1000)
        self.assertEqual(kinds(events), ["baseline"])
        self.assertTrue(all(d.approved for d in self.store.devices()))
        self.assertEqual(self.store.get(LAPTOP).hostname, "host-20")
        self.assertEqual(self.monitor.process(scan(*self.home), now=1060), [])

    def test_new_device_alerts_once_and_stays_unapproved(self):
        self.monitor.process(scan(*self.home), now=1000)
        events = self.monitor.process(scan(*self.home, ("192.168.1.50", STRANGER)), now=1060)
        self.assertEqual(kinds(events), ["new_device"])
        self.assertEqual(events[0].severity, "warning")
        self.assertIn(STRANGER, events[0].message)
        self.assertFalse(self.store.get(STRANGER).approved)
        self.assertEqual(self.monitor.process(scan(*self.home, ("192.168.1.50", STRANGER)), now=1120), [])

    def test_no_baseline_when_disabled(self):
        self.cfg.baseline_on_first_run = False
        events = self.monitor.process(scan(*self.home), now=1000)
        self.assertEqual(sorted(kinds(events)), ["new_device"] * 3)  # router, laptop and this host

    def test_offline_then_unapproved_return(self):
        self.monitor.process(scan(*self.home), now=1000)
        self.monitor.process(scan(*self.home, ("192.168.1.50", STRANGER)), now=1060)
        self.assertEqual(self.monitor.process(scan(*self.home), now=1200), [])  # not yet past offline_after
        events = self.monitor.process(scan(*self.home), now=1400)
        self.assertEqual(kinds(events), ["offline"])
        events = self.monitor.process(scan(*self.home, ("192.168.1.51", STRANGER)), now=1500)
        self.assertEqual(kinds(events), ["unapproved_return", "ip_change"])
        self.assertEqual(self.store.get(STRANGER).ips, ["192.168.1.51"])

    def test_approved_return_is_info(self):
        self.monitor.process(scan(*self.home), now=1000)
        self.monitor.process(scan(("192.168.1.1", ROUTER)), now=1400)
        events = self.monitor.process(scan(*self.home), now=1500)
        self.assertEqual([(e.kind, e.severity) for e in events], [("online", "info")])

    def test_ip_conflict_reported_once_per_conflict(self):
        self.monitor.process(scan(*self.home), now=1000)
        conflict = scan(*self.home, ("192.168.1.20", ATTACKER))
        events = self.monitor.process(conflict, now=1060)
        self.assertIn("ip_conflict", kinds(events))
        self.assertEqual([e.severity for e in events if e.kind == "ip_conflict"], ["critical"])
        self.assertNotIn("ip_conflict", kinds(self.monitor.process(conflict, now=1120)))
        self.monitor.process(scan(*self.home), now=1180)  # conflict clears
        self.assertIn("ip_conflict", kinds(self.monitor.process(conflict, now=1240)))

    def test_gateway_mac_change(self):
        self.monitor.process(scan(*self.home), now=1000)
        events = self.monitor.process(scan(("192.168.1.1", ATTACKER), ("192.168.1.20", LAPTOP)), now=1060)
        self.assertEqual(kinds(events), ["new_device", "gateway_change"])
        self.assertIn(ROUTER, events[1].message)

    def test_events_are_persisted(self):
        self.monitor.process(scan(*self.home), now=1000)
        self.monitor.process(scan(*self.home, ("192.168.1.50", STRANGER)), now=1060)
        self.assertEqual(kinds(self.store.events()), ["baseline", "new_device"])

    def test_cli_approval_survives_daemon_save(self):
        self.monitor.process(scan(*self.home, ("192.168.1.50", STRANGER)), now=1000)  # baseline: approved
        real_get = self.store.get
        stale = real_get(STRANGER)

        def get_then_cli_edits(mac):  # the CLI changes the device after the daemon has read it
            if mac != STRANGER:
                return real_get(mac)
            self.store.set_approved(STRANGER, False, "Mystery box")
            return stale

        with mock.patch.object(self.store, "get", get_then_cli_edits):
            self.monitor.process(scan(*self.home, ("192.168.1.50", STRANGER)), now=1060)
        device = self.store.get(STRANGER)
        self.assertEqual((device.approved, device.name), (False, "Mystery box"))


if __name__ == "__main__":
    unittest.main()
