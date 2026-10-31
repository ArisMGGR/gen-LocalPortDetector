import ipaddress
import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

from netsentry import notify, wizard
from netsentry.config import load_config
from netsentry.netutil import Interface
from netsentry.wizard import Wizard, update_config_text

PACKAGED_CONFIG = os.path.join(os.path.dirname(__file__), "..", "packaging", "netsentry.conf")
ETH0 = Interface("eth0", "02:00:00:00:00:01", "192.168.1.2", ipaddress.IPv4Network("192.168.1.0/24"), "192.168.1.1")


class UpdateConfigTextTest(unittest.TestCase):
    def test_replaces_values_and_keeps_comments(self):
        text = "[ntfy]\n# the topic\nurl =\n# url = https://example\ntoken =\n"
        result = update_config_text(text, {"ntfy": {"url": "https://ntfy.sh/abc"}})
        self.assertEqual(result, "[ntfy]\n# the topic\nurl = https://ntfy.sh/abc\n# url = https://example\ntoken =\n")

    def test_adds_missing_options_after_the_last_option_of_their_section(self):
        text = "[scan]\ninterval = 60\n\n# --- channels ---\n[ntfy]\nurl =\n"
        result = update_config_text(text, {"scan": {"interface": "eth0"}})
        self.assertEqual(result, "[scan]\ninterval = 60\ninterface = eth0\n\n# --- channels ---\n[ntfy]\nurl =\n")

    def test_adds_missing_sections_and_drops_replaced_continuation_lines(self):
        text = "[email]\nrecipients = a@example.com,\n    b@example.com\nport = 587\n"
        result = update_config_text(text, {"email": {"recipients": "c@example.com"}, "webhook": {"url": "https://x"}})
        self.assertEqual(result, "[email]\nrecipients = c@example.com\nport = 587\n\n[webhook]\nurl = https://x\n")

    def test_packaged_config_stays_valid(self):
        with open(PACKAGED_CONFIG, encoding="utf-8") as fh:
            text = update_config_text(fh.read(), {"email": {"host": "smtp.example.com", "sender": "a@example.com",
                                                            "recipients": "b@example.com"}})
        self.assertIn("# 587 with starttls, 465 with ssl", text)
        path = os.path.join(tempfile.mkdtemp(), "netsentry.conf")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.assertEqual(load_config(path).email.recipients, ["b@example.com"])
        finally:
            shutil.rmtree(os.path.dirname(path))


class WizardTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "netsentry.conf")
        with open(PACKAGED_CONFIG, encoding="utf-8") as fh:
            text = update_config_text(fh.read(), {"storage": {"database": os.path.join(self.dir, "devices.db")}})
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.posts = []
        patches = [mock.patch.object(wizard, "resolve_interface", return_value=ETH0),
                   mock.patch.object(notify, "_post", lambda url, data, headers: self.posts.append(url))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_wizard(self, answers, secrets=()):
        answers, secrets, prompts = iter(answers), iter(secrets), []

        def answer(prompt):
            prompts.append(prompt)
            return next(answers)

        w = Wizard(self.path, load_config(self.path), input_fn=answer,
                   password_fn=lambda prompt: next(secrets), out=io.StringIO())
        result = w.run()
        self.assertRaises(StopIteration, next, answers)  # every scripted answer was asked for
        return result, prompts, w

    def test_ntfy_setup_writes_config_and_sends_test(self):
        result, prompts, w = self.run_wizard([
            "",                 # watch the detected network
            "1",                # set up ntfy
            "",                 # default server
            "netsentry-test",   # topic
            "",                 # press Enter once subscribed
            "",                 # send a test
            "y",                # it arrived
            "4",                # done
            "",                 # no chatty alerts
            "n",                # don't trust current devices
            "",                 # save
        ], secrets=[""])
        self.assertEqual(result, 0)
        self.assertTrue(w.saved)
        self.assertEqual(self.posts, ["https://ntfy.sh/netsentry-test"])
        cfg = load_config(self.path)
        self.assertEqual(cfg.ntfy.url, "https://ntfy.sh/netsentry-test")
        self.assertFalse(cfg.detection.baseline_on_first_run)
        self.assertEqual(cfg.scan.interface, "")  # auto-detection kept
        with open(self.path, encoding="utf-8") as fh:
            self.assertIn("# Phone push notifications via https://ntfy.sh", fh.read())

    def test_email_setup_retries_after_failed_test_and_masks_password(self):
        failures = iter([OSError("connection refused")])

        def fake_send(channel, *args):
            error = next(failures, None)
            if error:
                raise error

        with mock.patch.object(wizard.EmailChannel, "send", fake_send):
            result, prompts, w = self.run_wizard([
                "",                     # watch the detected network
                "3",                    # email
                "smtp.example.com",     # host
                "",                     # starttls
                "",                     # port 587
                "me@example.com",       # username
                "",                     # from = username
                "",                     # to = from
                "",                     # send a test -> fails
                "",                     # try again
                "smtp2.example.com",    # host
                "",                     # starttls
                "",                     # port
                "",                     # username kept
                "",                     # from kept
                "",                     # to kept
                "",                     # send a test -> works
                "",                     # it arrived
                "4",                    # done
                "",                     # no chatty alerts
                "",                     # trust current devices
                "",                     # save
            ], secrets=["app-password", ""])
        self.assertEqual(result, 0)
        cfg = load_config(self.path)
        self.assertEqual((cfg.email.host, cfg.email.password, cfg.email.recipients),
                         ("smtp2.example.com", "app-password", ["me@example.com"]))
        summary = w.out.getvalue()
        self.assertIn("[email] password = (set)", summary)
        self.assertNotIn("app-password", summary)

    def test_declining_to_save_leaves_the_file_alone(self):
        with open(self.path, encoding="utf-8") as fh:
            before = fh.read()
        result, _, w = self.run_wizard(["", "4", "y", "y", "", "n"])  # no channel, continue anyway, chatty
        self.assertEqual(result, 0)
        self.assertFalse(w.saved)
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)


if __name__ == "__main__":
    unittest.main()
