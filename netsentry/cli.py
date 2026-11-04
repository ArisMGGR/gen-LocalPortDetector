"""Command-line interface: `netsentry <command>`."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sqlite3
import sys
import time
from dataclasses import asdict
from typing import Dict, List, Optional

from . import __version__
from .config import DEFAULT_CONFIG_PATH, Config, ConfigError, load_config
from .netutil import arp_scan, normalize_mac, resolve_hostnames, resolve_interface
from .notify import Notifier
from .oui import OuiDB
from .store import Device, Event, Store
from .systemd import setup_logging


class CliError(Exception):
    pass


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup = args.command == "setup"
    path = args.config or DEFAULT_CONFIG_PATH
    try:
        cfg = load_config(path, required=args.config is not None and not setup)
    except PermissionError:
        print(f"netsentry: permission denied reading {path} (try sudo)", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"netsentry: {exc}", file=sys.stderr)
        if not setup:
            return 78
        print("netsentry: setup will start from the default settings", file=sys.stderr)
        cfg = Config()
    setup_logging(cfg.general.log_level)
    try:
        return args.func(args, cfg)
    except PermissionError:
        print("netsentry: permission denied; raw sockets and the device database need root (try sudo)",
              file=sys.stderr)
    except sqlite3.Error as exc:
        print(f"netsentry: database error: {exc} (try sudo)", file=sys.stderr)
    except (CliError, RuntimeError, ValueError) as exc:
        print(f"netsentry: {exc}", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netsentry",
                                     description="Track the devices on your LAN and alert when unknown ones appear.")
    parser.add_argument("-c", "--config", help=f"config file (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("setup", help="answer a few questions to configure notifications and start the service")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("run", help="run the monitoring daemon (what the systemd service does)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("scan", help="scan once and print what is on the network")
    p.add_argument("-i", "--interface", help="interface to scan (default: from config, else default route)")
    p.add_argument("-s", "--subnet", help="subnet to sweep, e.g. 192.168.1.0/24")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("list", help="list known devices")
    p.add_argument("-u", "--unapproved", action="store_true", help="only unapproved devices")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("approve", help="mark a device as trusted (or rename it)")
    p.add_argument("mac", nargs="?", help="MAC address")
    p.add_argument("-n", "--name", help="friendly name, e.g. 'Living room TV'")
    p.add_argument("--all", action="store_true", help="approve every unapproved device")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("revoke", help="mark a device as untrusted again")
    p.add_argument("mac")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("forget", help="delete a device; it will alert as new if it shows up again")
    p.add_argument("mac")
    p.set_defaults(func=cmd_forget)

    p = sub.add_parser("events", help="show recent events")
    p.add_argument("-n", "--limit", type=int, default=50, help="number of events (default: 50)")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("test-notify", help="send a test alert through every configured channel")
    p.set_defaults(func=cmd_test_notify)
    return parser


def cmd_setup(args: argparse.Namespace, cfg: Config) -> int:
    from .wizard import Wizard

    if not sys.stdin.isatty():
        raise CliError("setup asks questions, so run it in a terminal")
    wizard = Wizard(args.config or DEFAULT_CONFIG_PATH, cfg,
                    preview=lambda c: cmd_scan(argparse.Namespace(interface=None, subnet=None), c))
    try:
        return wizard.run()
    except (KeyboardInterrupt, EOFError):
        print("\nSetup cancelled." + ("" if wizard.saved else " Nothing was saved."), file=sys.stderr)
        return 130


def cmd_run(args: argparse.Namespace, cfg: Config) -> int:
    from .daemon import Daemon

    return Daemon(cfg).run()


def cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    iface = resolve_interface(args.interface or cfg.scan.interface, args.subnet or cfg.scan.subnet)
    print(f"Scanning {iface.network} on {iface.name} ...", file=sys.stderr)
    scan = arp_scan(iface, cfg.scan.timeout, cfg.scan.passes, cfg.scan.max_hosts)
    devices = scan.by_mac()
    names = resolve_hostnames(ips[0] for ips in devices.values()) if cfg.scan.resolve_hostnames else {}
    known = _known_devices(cfg)
    oui = OuiDB(cfg.storage.oui_file)

    rows = []
    for mac, ips in sorted(devices.items(), key=lambda item: ipaddress.IPv4Address(item[1][0])):
        device = known.get(mac) if known is not None else None
        if mac == iface.mac:
            status = "this host"
        elif known is None:
            status = "-"
        elif device is None:
            status = "NEW"
        else:
            status = "approved" if device.approved else "UNAPPROVED"
        rows.append([", ".join(ips), mac, status, device.name if device else "",
                     names.get(ips[0], ""), oui.lookup(mac)])
    _print_table(["IP", "MAC", "STATUS", "NAME", "HOSTNAME", "VENDOR"], rows)
    for ip, macs in sorted(scan.conflicts().items()):
        print(f"WARNING: {ip} was claimed by several MACs: {', '.join(sorted(macs))}", file=sys.stderr)
    print(f"{len(devices)} devices found", file=sys.stderr)
    return 0


def cmd_list(args: argparse.Namespace, cfg: Config) -> int:
    with _open_store(cfg) as store:
        devices = store.devices(args.unapproved)
    if args.json:
        print(json.dumps([asdict(d) for d in devices], indent=2))
        return 0
    rows = [[d.mac, ", ".join(d.ips), "yes" if d.approved else "NO", "online" if d.online else "offline",
             d.name, d.hostname, d.vendor, _fmt_time(d.first_seen), _fmt_time(d.last_seen)] for d in devices]
    _print_table(["MAC", "IP", "APPROVED", "STATE", "NAME", "HOSTNAME", "VENDOR", "FIRST SEEN", "LAST SEEN"], rows)
    return 0


def cmd_approve(args: argparse.Namespace, cfg: Config) -> int:
    if bool(args.mac) == args.all:
        raise CliError("give either a MAC address or --all")
    if args.all and args.name:
        raise CliError("--name needs a MAC address; it can't be used with --all")
    with _open_store(cfg) as store:
        if args.all:
            print(f"Approved {store.approve_all()} device(s).")
            return 0
        mac = normalize_mac(args.mac)
        if not store.set_approved(mac, True, args.name):
            raise CliError(f"unknown device {mac} (see 'netsentry list')")
    print(f"Approved {mac}" + (f" as {args.name!r}" if args.name else ""))
    return 0


def cmd_revoke(args: argparse.Namespace, cfg: Config) -> int:
    mac = normalize_mac(args.mac)
    with _open_store(cfg) as store:
        if not store.set_approved(mac, False):
            raise CliError(f"unknown device {mac}")
    print(f"Revoked approval for {mac}")
    return 0


def cmd_forget(args: argparse.Namespace, cfg: Config) -> int:
    mac = normalize_mac(args.mac)
    with _open_store(cfg) as store:
        if not store.forget(mac):
            raise CliError(f"unknown device {mac}")
    print(f"Forgot {mac}")
    return 0


def cmd_events(args: argparse.Namespace, cfg: Config) -> int:
    with _open_store(cfg) as store:
        for e in store.events(args.limit):
            print(f"{_fmt_time(e.ts)}  {e.severity.upper():<8}  {e.kind:<17}  {e.message}")
    return 0


def cmd_test_notify(args: argparse.Namespace, cfg: Config) -> int:
    notifier = Notifier(cfg)
    if not notifier.channels:
        raise CliError("no notification channels are configured; set [ntfy], [webhook] or [email] in the config")
    event = Event("test", "warning", "This is a test alert from netsentry. If you can read this, notifications work.")
    failures = notifier.send([event], force=True)
    print(f"Sent through {len(notifier.channels) - failures} of {len(notifier.channels)} channel(s).")
    return 1 if failures else 0


def _open_store(cfg: Config) -> Store:
    # Never create the database from the CLI: as root it would end up owned by root,
    # and the unprivileged service user could no longer write to it.
    if not os.path.exists(cfg.storage.database):
        raise CliError(f"no device database at {cfg.storage.database} yet; start the service first "
                       "(systemctl start netsentry)")
    return Store(cfg.storage.database)


def _known_devices(cfg: Config) -> Optional[Dict[str, Device]]:
    """Devices from the database for status display, or None if it isn't available."""
    if not os.path.exists(cfg.storage.database):
        return None
    try:
        with Store(cfg.storage.database) as store:
            return {d.mac: d for d in store.devices()}
    except sqlite3.Error:
        return None


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _print_table(headers: List[str], rows: List[List[str]]) -> None:
    widths = [max(len(str(cell)) for cell in column) for column in zip(headers, *rows)]
    for row in [headers, *rows]:
        print("  ".join(str(cell).ljust(width) for cell, width in zip(row, widths)).rstrip())
