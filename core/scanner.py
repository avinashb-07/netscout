"""
NetScout - Core Scanner Engine
Handles port scanning, host discovery, and service fingerprinting.
"""

import socket
import struct
import threading
import time
import ipaddress
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class PortResult:
    port: int
    protocol: str
    state: PortState
    service: str = ""
    banner: str = ""
    response_time_ms: float = 0.0


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    is_up: bool = False
    os_guess: str = ""
    ttl: int = 0
    ports: List[PortResult] = field(default_factory=list)
    scan_time_sec: float = 0.0
    mac_address: str = ""


# Well-known service name mapping (port → service name)
SERVICE_MAP: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp-client", 69: "tftp", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp", 194: "irc",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "printer", 520: "route",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel",
    2083: "cpanel-ssl", 2181: "zookeeper", 2375: "docker",
    2376: "docker-ssl", 3000: "dev-server", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4000: "terabase", 4369: "epmd",
    5000: "flask/upnp", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 7077: "spark", 8080: "http-alt",
    8081: "http-alt2", 8443: "https-alt", 8888: "jupyter",
    9000: "php-fpm", 9042: "cassandra", 9090: "prometheus",
    9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
    10250: "kubelet", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb-shard", 28017: "mongodb-http",
}

# TTL-based OS guessing heuristic
def guess_os_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return "Unknown"
    elif ttl <= 64:
        return "Linux/macOS (TTL≤64)"
    elif ttl <= 128:
        return "Windows (TTL≤128)"
    elif ttl <= 255:
        return "Cisco/Solaris (TTL≤255)"
    return "Unknown"


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner via TCP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send a generic probe
            try:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            except Exception:
                pass
            data = s.recv(1024)
            banner = data.decode("utf-8", errors="replace").strip()
            return banner[:200]  # cap length
    except Exception:
        return ""


def tcp_connect_scan(ip: str, port: int, timeout: float = 1.0) -> Tuple[PortState, float]:
    """TCP Connect scan — full 3-way handshake."""
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            elapsed = (time.time() - start) * 1000
            if result == 0:
                return PortState.OPEN, elapsed
            else:
                return PortState.CLOSED, elapsed
    except socket.timeout:
        elapsed = (time.time() - start) * 1000
        return PortState.FILTERED, elapsed
    except Exception:
        elapsed = (time.time() - start) * 1000
        return PortState.FILTERED, elapsed


def udp_scan(ip: str, port: int, timeout: float = 2.0) -> Tuple[PortState, float]:
    """UDP scan — sends empty datagram and checks for ICMP port unreachable."""
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00", (ip, port))
            try:
                s.recvfrom(1024)
                elapsed = (time.time() - start) * 1000
                return PortState.OPEN, elapsed
            except socket.timeout:
                elapsed = (time.time() - start) * 1000
                return PortState.OPEN_FILTERED, elapsed
    except Exception:
        elapsed = (time.time() - start) * 1000
        return PortState.FILTERED, elapsed


def ping_host(ip: str, timeout: float = 1.5) -> Tuple[bool, int]:
    """
    ICMP ping using raw socket. Falls back to TCP-based detection on permission error.
    Returns (is_up, ttl).
    """
    try:
        # Build ICMP echo request
        icmp_proto = socket.getprotobyname("icmp")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
        sock.settimeout(timeout)

        # ICMP header: type=8, code=0, checksum=0, id=1, seq=1
        header = struct.pack("bbHHh", 8, 0, 0, 1, 1)
        data = b"NetScout-Probe"
        chksum = _icmp_checksum(header + data)
        header = struct.pack("bbHHh", 8, 0, chksum, 1, 1)
        packet = header + data

        sock.sendto(packet, (ip, 0))
        start = time.time()
        while time.time() - start < timeout:
            try:
                recv_packet, _ = sock.recvfrom(1024)
                ttl = recv_packet[8]  # TTL field in IP header
                icmp_type = recv_packet[20]
                if icmp_type == 0:  # Echo reply
                    sock.close()
                    return True, ttl
            except socket.timeout:
                break
        sock.close()
        return False, 0
    except PermissionError:
        # Fallback: try TCP connect on common ports
        return _tcp_ping(ip, timeout), 64
    except Exception:
        return False, 0


def _tcp_ping(ip: str, timeout: float) -> bool:
    """Fallback ping using TCP connect to port 80 or 443."""
    for port in [80, 443, 22, 8080]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def _icmp_checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i + 1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def expand_targets(target_str: str) -> List[str]:
    """
    Parse target string into list of IPs.
    Supports: single IP, CIDR range (192.168.1.0/24), range (192.168.1.1-20),
    hostname, comma-separated list.
    """
    targets = []
    for part in target_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            # Try CIDR
            network = ipaddress.ip_network(part, strict=False)
            targets.extend(str(ip) for ip in network.hosts())
        except ValueError:
            # Try hostname
            try:
                ip = socket.gethostbyname(part)
                targets.append(ip)
            except socket.gaierror:
                # Try range like 192.168.1.1-20
                if "-" in part:
                    base, end = part.rsplit("-", 1)
                    base_parts = base.split(".")
                    try:
                        start_n = int(base_parts[-1])
                        end_n = int(end)
                        prefix = ".".join(base_parts[:-1])
                        for n in range(start_n, end_n + 1):
                            targets.append(f"{prefix}.{n}")
                    except ValueError:
                        pass
    return list(dict.fromkeys(targets))  # deduplicate, preserve order


def parse_ports(port_str: str) -> List[int]:
    """
    Parse port string into list.
    Supports: 80, 22-100, 80,443,8080, 'top100', 'top1000', 'all'
    """
    if port_str.lower() == "all":
        return list(range(1, 65536))
    if port_str.lower() == "top100":
        return TOP_100_PORTS
    if port_str.lower() == "top1000":
        return TOP_1000_PORTS

    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


class Scanner:
    """Main scanner orchestrator."""

    def __init__(
        self,
        targets: List[str],
        ports: List[int],
        protocol: str = "tcp",
        threads: int = 100,
        timeout: float = 1.0,
        grab_banners: bool = True,
        skip_ping: bool = False,
        verbose: bool = False,
        progress_callback=None,
    ):
        self.targets = targets
        self.ports = ports
        self.protocol = protocol
        self.threads = threads
        self.timeout = timeout
        self.grab_banners = grab_banners
        self.skip_ping = skip_ping
        self.verbose = verbose
        self.progress_callback = progress_callback
        self._lock = threading.Lock()
        self._scanned = 0
        self._total = len(targets) * len(ports)

    def scan(self) -> List[HostResult]:
        results = []
        for ip in self.targets:
            result = self._scan_host(ip)
            results.append(result)
        return results

    def _scan_host(self, ip: str) -> HostResult:
        host = HostResult(ip=ip)
        start = time.time()

        # Host discovery
        if self.skip_ping:
            host.is_up = True
            host.ttl = 64
        else:
            is_up, ttl = ping_host(ip, self.timeout)
            host.is_up = is_up
            host.ttl = ttl

        host.hostname = resolve_hostname(ip)
        host.os_guess = guess_os_from_ttl(host.ttl)

        if not host.is_up:
            host.scan_time_sec = time.time() - start
            return host

        # Port scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {
                ex.submit(self._scan_port, ip, p): p for p in self.ports
            }
            for future in concurrent.futures.as_completed(futures):
                port_result = future.result()
                if port_result:
                    with self._lock:
                        host.ports.append(port_result)
                        self._scanned += 1
                        if self.progress_callback:
                            self.progress_callback(self._scanned, self._total)

        # Sort ports
        host.ports.sort(key=lambda r: r.port)
        host.scan_time_sec = time.time() - start
        return host

    def _scan_port(self, ip: str, port: int) -> Optional[PortResult]:
        if self.protocol == "tcp":
            state, rtt = tcp_connect_scan(ip, port, self.timeout)
        else:
            state, rtt = udp_scan(ip, port, self.timeout)

        service = SERVICE_MAP.get(port, "unknown")

        banner = ""
        if self.grab_banners and state == PortState.OPEN and self.protocol == "tcp":
            banner = grab_banner(ip, port, self.timeout)

        if state in (PortState.OPEN, PortState.OPEN_FILTERED):
            return PortResult(
                port=port,
                protocol=self.protocol,
                state=state,
                service=service,
                banner=banner,
                response_time_ms=rtt,
            )
        return None


# ─── Port Lists ───────────────────────────────────────────────────────────────

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 123, 135, 139, 143, 161, 179,
    194, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636, 993, 995,
    1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376, 3000,
    3306, 3389, 3690, 4369, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443,
    7077, 8080, 8081, 8443, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 10250,
    11211, 15672, 27017, 27018, 28017,
]

TOP_1000_PORTS = TOP_100_PORTS + list(range(1024, 1024 + (1000 - len(TOP_100_PORTS))))
TOP_1000_PORTS = sorted(set(TOP_1000_PORTS))[:1000]
