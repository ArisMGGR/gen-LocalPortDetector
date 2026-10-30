import os
import tempfile
import unittest
from unittest import mock

from netsentry import notify
from netsentry.config import ConfigError, load_config
from netsentry.oui import parse_oui_file
from netsentry.store import Event

PACKAGED_CONFIG = os.path.join(os.path.dirname(__file__), "..", "packaging", "netsentry.conf")


def write_temp(text):
    fh = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False, encoding="utf-8")
    fh.write(text)
    fh.close()
    return fh.name


class ConfigTest(unittest.TestCase):
    def test_packaged_config_matches_defaults(self):
        cfg = load_config(PACKAGED_CONFIG)
        self.assertEqual(cfg.scan.interval, 60)
        self.assertEqual(cfg.email.recipients, [])
        self.assertTrue(cfg.detection.baseline_on_first_run)

    def test_values_are_typed(self):
        path = write_temp("[scan]\ninterval = 30\ntimeout = 1.5\nresolve_hostnames = no\n"
                          "[email]\nhost = smtp.example.com\nsender = a@example.com\n"
                          "recipients = b@example.com, c@example.com\npassword = 100%secret\n")
        try:
            cfg = load_config(path)
        finally:
            os.unlink(path)
        self.assertEqual((cfg.scan.interval, cfg.scan.timeout, cfg.scan.resolve_hostnames), (30, 1.5, False))
        self.assertEqual(cfg.email.recipients, ["b@example.com", "c@example.com"])
        self.assertEqual(cfg.email.password, "100%secret")

    def test_rejects_typos_and_bad_values(self):
        for text in ("[scan]\nintervall = 30\n", "[scna]\n", "[scan]\ninterval = 5\n",
                     "[scan]\nsubnet = 192.168.1.0/33\n", "[email]\nhost = smtp.example.com\n"):
            path = write_temp(text)
            try:
                with self.assertRaises(ConfigError, msg=text):
                    load_config(path)
            finally:
                os.unlink(path)

    def test_missing_optional_config_uses_defaults(self):
        self.assertEqual(load_config("/nonexistent.conf", required=False).scan.interval, 60)
        with self.assertRaises(ConfigError):
            load_config("/nonexistent.conf")


class NotifyTest(unittest.TestCase):
    def test_summarize_batches_and_picks_worst_severity(self):
        events = [Event("new_device", "warning", "one"), Event("ip_conflict", "critical", "two")]
        title, body, severity = notify.summarize(events, "pi")
        self.assertEqual((title, severity), ("[pi] 2 network alerts", "critical"))
        self.assertEqual(body, "- one\n- two")

    def test_notifier_filters_by_severity_and_survives_channel_errors(self):
        cfg = load_config(PACKAGED_CONFIG)
        cfg.ntfy.url = "https://ntfy.example/topic"
        cfg.webhook.url = "https://hooks.example/x"
        cfg.webhook.format = "discord"
        notifier = notify.Notifier(cfg)
        calls = []

        def fake_post(url, data, headers):
            calls.append((url, data, headers))
            if "ntfy" in url:
                raise OSError("connection refused")

        with mock.patch.object(notify, "_post", fake_post):
            self.assertEqual(notifier.send([Event("offline", "info", "quiet")]), 0)
            self.assertEqual(calls, [])
            self.assertEqual(notifier.send([Event("gateway_change", "critical", "alarm")]), 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][2]["Priority"], "urgent")
        self.assertIn(b'"content"', calls[1][1])


class OuiTest(unittest.TestCase):
    def test_parses_common_formats(self):
        path = write_temp("00-00-0C   (hex)\t\tCisco Systems, Inc\n"
                          "00000C     (base 16)\t\tCisco Systems, Inc\n"
                          "001A2B Ayecom Technology\n"
                          "00:1B:63\tApple\tApple, Inc.\n"
                          "00:1B:C5:00:00:00/36\tConverging\tConverging Systems Inc.\n")
        try:
            table = parse_oui_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(table, {"00000C": "Cisco Systems, Inc", "001A2B": "Ayecom Technology",
                                 "001B63": "Apple, Inc."})


if __name__ == "__main__":
    unittest.main()
