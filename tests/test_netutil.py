import ipaddress
import os
import tempfile
import unittest

from netsentry.netutil import (Interface, ScanResult, build_arp_request, is_randomized_mac, normalize_mac,
                               parse_arp, read_default_routes)

ROUTES = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""


class NetutilTest(unittest.TestCase):
    def test_arp_request_round_trip(self):
        frame = build_arp_request(bytes.fromhex("020000000001"), "192.168.1.10", "192.168.1.20")
        self.assertEqual(len(frame), 42)
        self.assertEqual(frame[:6], b"\xff" * 6)
        self.assertEqual(parse_arp(frame), (1, "02:00:00:00:00:01", "192.168.1.10"))

    def test_parse_rejects_non_arp(self):
        self.assertIsNone(parse_arp(b"\x00" * 12 + b"\x08\x00" + b"\x00" * 40))
        self.assertIsNone(parse_arp(b"short"))

    def test_normalize_mac(self):
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aabbccddeeff"), "aa:bb:cc:dd:ee:ff")
        with self.assertRaises(ValueError):
            normalize_mac("aa:bb:cc")

    def test_randomized_mac(self):
        self.assertTrue(is_randomized_mac("da:a1:19:00:00:01"))
        self.assertFalse(is_randomized_mac("00:1a:2b:3c:4d:5e"))

    def test_default_routes_sorted_by_metric(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(ROUTES)
        try:
            self.assertEqual(read_default_routes(fh.name), [("eth0", "10.0.0.1"), ("wlan0", "192.168.1.1")])
        finally:
            os.unlink(fh.name)

    def test_scan_result_grouping(self):
        iface = Interface("eth0", "02:00:00:00:00:01", "10.0.0.2", ipaddress.IPv4Network("10.0.0.0/24"))
        scan = ScanResult(iface)
        scan.add("10.0.0.10", "aa:aa:aa:aa:aa:aa")
        scan.add("10.0.0.9", "aa:aa:aa:aa:aa:aa")
        scan.add("10.0.0.10", "bb:bb:bb:bb:bb:bb")
        self.assertEqual(scan.by_mac()["aa:aa:aa:aa:aa:aa"], ["10.0.0.9", "10.0.0.10"])
        self.assertEqual(scan.conflicts(), {"10.0.0.10": {"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}})


if __name__ == "__main__":
    unittest.main()
