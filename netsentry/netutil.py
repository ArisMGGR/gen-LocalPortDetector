"""Linux network helpers: interface discovery and raw-socket ARP scanning."""
from __future__ import annotations

import errno
import ipaddress
import re
import select
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

ETH_P_ARP = 0x0806
ARP_REQUEST = 1
PACKET_OUTGOING = 4
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
RTF_GATEWAY = 0x2
BROADCAST_MAC = b"\xff" * 6
ZERO_MAC = b"\x00" * 6
_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def normalize_mac(value: str) -> str:
    """Return *value* as a lowercase colon-separated MAC, raising ValueError if invalid."""
    mac = value.strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", mac):
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    if not _MAC_RE.fullmatch(mac):
        raise ValueError(f"invalid MAC address: {value!r}")
    return mac


def is_randomized_mac(mac: str) -> bool:
    """True for locally administered MACs, e.g. the "private Wi-Fi address" of phones."""
    return bool(int(mac[:2], 16) & 0x02)


@dataclass
class Interface:
    name: str
    mac: str
    ip: str
    network: ipaddress.IPv4Network
    gateway: Optional[str] = None


@dataclass
class ScanResult:
    interface: Interface
    claims: Dict[str, Set[str]] = field(default_factory=dict)  # IP -> MACs that answered for it

    def add(self, ip: str, mac: str) -> None:
        self.claims.setdefault(ip, set()).add(mac)

    def by_mac(self) -> Dict[str, List[str]]:
        devices: Dict[str, List[str]] = {}
        for ip, macs in self.claims.items():
            for mac in macs:
                devices.setdefault(mac, []).append(ip)
        return {mac: sorted(ips, key=ipaddress.IPv4Address) for mac, ips in devices.items()}

    def conflicts(self) -> Dict[str, Set[str]]:
        return {ip: macs for ip, macs in self.claims.items() if len(macs) > 1}


def read_default_routes(path: str = "/proc/net/route") -> List[Tuple[str, str]]:
    """Return (interface, gateway IP) pairs for IPv4 default routes, lowest metric first."""
    routes = []
    with open(path) as fh:
        next(fh, None)  # header line
        for line in fh:
            parts = line.split()
            if len(parts) < 7:
                continue
            iface, dest, gateway, flags = parts[:4]
            if dest == "00000000" and int(flags, 16) & RTF_GATEWAY:
                routes.append((int(parts[6]), iface, socket.inet_ntoa(struct.pack("=L", int(gateway, 16)))))
    return [(iface, gw) for _, iface, gw in sorted(routes)]


def _ioctl_ipv4(name: str, request: int) -> str:
    import fcntl  # Linux only, so imported lazily

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        packed = struct.pack("256s", name.encode()[:15])
        return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), request, packed)[20:24])


def resolve_interface(name: str = "", subnet: str = "") -> Interface:
    """Look up address, MAC, subnet and gateway of *name* (default: the default-route interface)."""
    routes = read_default_routes()
    if not name:
        if not routes:
            raise RuntimeError("no default route found; set [scan] interface in the config")
        name = routes[0][0]
    try:
        ip = _ioctl_ipv4(name, SIOCGIFADDR)
        netmask = _ioctl_ipv4(name, SIOCGIFNETMASK)
    except OSError as exc:
        raise RuntimeError(f"interface {name} has no IPv4 address ({exc.strerror})") from exc
    try:
        with open(f"/sys/class/net/{name}/address") as fh:
            mac = normalize_mac(fh.read())
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read the MAC address of {name}: {exc}") from exc
    if subnet:
        network = ipaddress.IPv4Network(subnet, strict=False)
    else:
        network = ipaddress.IPv4Interface(f"{ip}/{netmask}").network
    gateway = next((gw for iface, gw in routes if iface == name), None)
    return Interface(name, mac, ip, network, gateway)


def build_arp_request(src_mac: bytes, src_ip: str, target_ip: str) -> bytes:
    ethernet = struct.pack("!6s6sH", BROADCAST_MAC, src_mac, ETH_P_ARP)
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, ARP_REQUEST,
                      src_mac, socket.inet_aton(src_ip), ZERO_MAC, socket.inet_aton(target_ip))
    return ethernet + arp


def parse_arp(frame: bytes) -> Optional[Tuple[int, str, str]]:
    """Return (opcode, sender MAC, sender IP) for an Ethernet/IPv4 ARP frame, else None."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    htype, ptype, hlen, plen, op, sha, spa = struct.unpack_from("!HHBBH6s4s", frame, 14)
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
        return None
    return op, mac_to_str(sha), socket.inet_ntoa(spa)


def arp_scan(iface: Interface, timeout: float = 2.0, passes: int = 2, max_hosts: int = 4096) -> ScanResult:
    """Sweep iface.network with ARP requests and collect every answer. Needs root or CAP_NET_RAW."""
    network = iface.network
    if network.num_addresses - 2 > max_hosts:
        raise RuntimeError(f"{network} has {network.num_addresses - 2} hosts, above max_hosts={max_hosts}; "
                           "set a narrower [scan] subnet")
    targets = [str(host) for host in network.hosts() if str(host) != iface.ip]
    src_mac = bytes.fromhex(iface.mac.replace(":", ""))
    result = ScanResult(iface)
    result.add(iface.ip, iface.mac)

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP)) as sock:
        sock.bind((iface.name, 0))
        for _ in range(passes):
            for i, target in enumerate(targets, 1):
                _send(sock, build_arp_request(src_mac, iface.ip, target), result)
                if i % 32 == 0:
                    _collect(sock, result, 0.005)  # pace the sweep and keep the receive buffer drained
        _collect(sock, result, timeout)
    return result


def _send(sock: socket.socket, frame: bytes, result: ScanResult) -> None:
    for _ in range(3):
        try:
            sock.send(frame)
            return
        except OSError as exc:
            if exc.errno not in (errno.ENOBUFS, errno.EAGAIN):
                raise
            _collect(sock, result, 0.05)


def _collect(sock: socket.socket, result: ScanResult, duration: float) -> None:
    network = result.interface.network
    deadline = time.monotonic() + duration
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sock], [], [], remaining)[0]:
            return
        frame, addr = sock.recvfrom(65535)
        if addr[2] == PACKET_OUTGOING:
            continue
        parsed = parse_arp(frame)
        if parsed is None:
            continue
        _, mac, ip = parsed
        # Requests from other hosts count too (passive discovery); 0.0.0.0 is an RFC 5227 probe.
        if ip != "0.0.0.0" and ipaddress.IPv4Address(ip) in network:
            result.add(ip, mac)


def resolve_hostnames(ips: Iterable[str], timeout: float = 3.0) -> Dict[str, str]:
    """Reverse-DNS lookups in parallel; addresses that don't resolve in time are left out."""
    ips = list(ips)
    if not ips:
        return {}
    pool = ThreadPoolExecutor(max_workers=min(8, len(ips)))
    futures = {pool.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    done, _ = wait(futures, timeout=timeout)
    pool.shutdown(wait=False)
    return {futures[f]: f.result()[0] for f in done if f.exception() is None}
