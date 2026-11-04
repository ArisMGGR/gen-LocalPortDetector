import ipaddress
import logging
import os
import tempfile
import time
import unittest
from unittest import mock

from netsentry.config import Config
from netsentry.daemon import Daemon
from netsentry.dailylog import DailyLog
from netsentry.netutil import Interface, ScanResult
from netsentry.store import Event

SELF = "02:00:00:00:00:01"
STRANGER = "00:de:ad:be:ef:01"
IFACE = Interface("eth0", SELF, "192.168.1.2", ipaddress.IPv4Network("192.168.1.0/24"), "")

logging.getLogger("netsentry.daemon").addHandler(logging.NullHandler())  # events would print during the tests


def scan(*claims):
    result = ScanResult(IFACE)
    result.add("192.168.1.2", SELF)
    for ip, mac in claims:
        result.add(ip, mac)
    return result


def day(text):
    return time.mktime(time.strptime(text + " 12:00:00", "%Y-%m-%d %H:%M:%S"))


class DailyLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "logs")
        self.log = DailyLog(self.dir)

    def read(self, name):
        with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
            return fh.read()

    def test_each_day_gets_its_own_file(self):
        self.log.write("INFO", "first", day("2026-11-04"))
        self.log.write("WARNING", "second", day("2026-11-05"))
        self.assertEqual(sorted(os.listdir(self.dir)), ["2026-11-04.log", "2026-11-05.log"])
        self.assertEqual(self.read("2026-11-05.log"), "2026-11-05 12:00:00 [WARNING] second\n")

    def test_line_break_cannot_forge_a_line(self):
        self.log.write("WARNING", "host\n2026-11-04 12:00:00 [INFO] server all good", day("2026-11-04"))
        self.assertEqual(self.read("2026-11-04.log").count("\n"), 1)

    def test_prune_removes_only_old_day_files(self):
        self.log.write("INFO", "old", day("2026-01-01"))
        self.log.write("INFO", "new", day("2026-11-04"))
        with open(os.path.join(self.dir, "notes.log"), "w", encoding="utf-8"):
            pass
        self.assertEqual(self.log.prune(day("2026-11-01")), 1)
        self.assertEqual(sorted(os.listdir(self.dir)), ["2026-11-04.log", "notes.log"])

    def test_prune_without_a_folder_yet(self):
        self.assertEqual(self.log.prune(day("2026-11-01")), 0)

    def test_empty_directory_disables_it(self):
        DailyLog("").write("INFO", "nothing")
        self.assertEqual(DailyLog("").prune(day("2026-11-01")), 0)

    def test_unwritable_folder_is_reported_not_raised(self):
        with open(os.path.join(self.tmp.name, "file"), "w", encoding="utf-8"):
            pass
        with self.assertLogs("netsentry.dailylog", "ERROR"):
            DailyLog(os.path.join(self.tmp.name, "file", "logs")).write("INFO", "x")


class DaemonCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = Config()
        cfg.storage.database = ":memory:"
        cfg.storage.event_log = ""
        cfg.storage.oui_file = "/nonexistent"
        cfg.storage.daily_log_dir = os.path.join(self.tmp.name, "logs")
        cfg.scan.resolve_hostnames = False
        self.daemon = Daemon(cfg)
        self.addCleanup(self.daemon.store.close)
        self.cycle()  # the baseline
        self.check()  # its warning counts against the first window

    def cycle(self, *claims):
        with mock.patch("netsentry.daemon.resolve_interface", return_value=IFACE), \
                mock.patch("netsentry.daemon.arp_scan", return_value=scan(*claims)):
            self.daemon.cycle()

    def check(self):
        self.daemon._next_check = 0
        self.daemon._daily_check()

    def lines(self):
        directory = self.daemon.cfg.storage.daily_log_dir
        text = ""
        for name in sorted(os.listdir(directory)):
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                text += fh.read()
        return text.splitlines()

    def test_quiet_window_says_all_good(self):
        before = self.lines()
        self.cycle()
        self.check()
        self.assertEqual(len(self.lines()), len(before) + 1)
        self.assertTrue(self.lines()[-1].endswith("[INFO] server all good"))

    def test_check_waits_for_its_interval(self):
        before = self.lines()
        self.daemon._next_check = time.monotonic() + 60
        self.daemon._daily_check()
        self.assertEqual(self.lines(), before)

    def test_new_device_blocks_all_good_until_approved(self):
        self.cycle(("192.168.1.50", STRANGER))
        self.check()
        text = "\n".join(self.lines())
        self.assertIn("[WARNING] new_device:", text)
        self.assertIn(f"[WARNING] Unapproved device online: {STRANGER}", text)
        self.assertNotIn("server all good", text)
        self.check()
        self.assertNotIn("server all good", "\n".join(self.lines()))

        self.daemon.store.set_approved(STRANGER, True)
        self.check()
        self.assertTrue(self.lines()[-1].endswith("server all good"))

    def test_scan_error_blocks_all_good_for_that_window(self):
        def fail():
            self.daemon.stopping.set()
            raise RuntimeError("no IPv4 address on eth0")

        with mock.patch.object(self.daemon, "cycle", side_effect=fail), \
                mock.patch.object(self.daemon.store, "close"):
            with self.assertLogs("netsentry.daemon", "ERROR"):
                self.daemon.run()
        self.assertIn("[ERROR] scan skipped: no IPv4 address on eth0", self.lines()[-1])
        self.check()
        self.assertNotIn("server all good", "\n".join(self.lines()))
        self.check()
        self.assertTrue(self.lines()[-1].endswith("server all good"))

    def test_info_events_do_not_block_all_good(self):
        self.daemon._daily_events([Event("offline", "info", "Device went offline")])
        self.check()
        self.assertIn("[INFO] offline: Device went offline", "\n".join(self.lines()))
        self.assertTrue(self.lines()[-1].endswith("server all good"))


if __name__ == "__main__":
    unittest.main()
