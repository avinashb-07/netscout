"""
NetScout - Utility Helpers
Network utilities, service probes, and fingerprinting helpers.
"""

import socket
import re
import ipaddress
from typing import Optional, Dict


# ─── Service-level probes ──────────────────────────────────────────────────────
# Probes keyed by port → bytes to send, pattern to parse from response.

SERVICE_PROBES: Dict[int, dict] = {
    21: {
        "send": b"",          # FTP sends banner on connect
        "pattern": r"220[\s-](.+)",
        "label": "FTP",
    },
    22: {
        "send": b"",          # SSH sends banner on connect
        "pattern": r"SSH-[\d.]+-(.+)",
        "label": "SSH",
    },
    25: {
        "send": b"EHLO netscout\r\n",
        "pattern": r"220[\s-](.+)",
        "label": "SMTP",
    },
    80: {
        "send": b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
        "pattern": r"Server:\s*(.+)",
        "label": "HTTP",
    },
    110: {
        "send": b"",
        "pattern": r"\+OK (.+)",
        "label": "POP3",
    },
    143: {
        "send": b"",
        "pattern": r"\* OK (.+)",
        "label": "IMAP",
    },
    443: {
        "send": b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
        "pattern": r"Server:\s*(.+)",
        "label": "HTTPS",
    },
    3306: {
        "send": b"",
        "pattern": r"[\x00-\xff]{4}(.+)",   # MySQL greeting
        "label": "MySQL",
    },
    5432: {
        "send": b"",
        "pattern": r"(.+)",
        "label": "PostgreSQL",
    },
    6379: {
        "send": b"PING\r\n",
        "pattern": r"\+PONG",
        "label": "Redis",
    },
    27017: {
        "send": b"",
        "pattern": r"(.+)",
        "label": "MongoDB",
    },
}


def enhanced_banner_grab(ip: str, port: int, timeout: float = 2.0) -> tuple[str, str]:
    """
    Try a targeted probe for the port's known service.
    Returns (banner_text, service_hint).
    """
    probe = SERVICE_PROBES.get(port, {})
    send_bytes = probe.get("send", b"HEAD / HTTP/1.0\r\n\r\n")
    pattern = probe.get("pattern", r"(.+)")
    label = probe.get("label", "")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Read initial banner first
            raw = b""
            try:
                raw = s.recv(512)
            except Exception:
                pass
            # Send probe if we have one
            if send_bytes:
                try:
                    s.send(send_bytes)
                    raw += s.recv(512)
                except Exception:
                    pass

            text = raw.decode("utf-8", errors="replace").strip()
            # Try to extract meaningful part
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                try:
                    hint = match.group(1).strip()[:120]
                except IndexError:
                    hint = text[:120]
                return hint, label
            return text[:120], label
    except Exception:
        return "", label


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    result = 0
    for p in parts:
        result = result * 256 + int(p)
    return result


def get_local_ip() -> str:
    """Get the machine's outbound IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_local_subnet() -> Optional[str]:
    """Best-guess local /24 subnet for the machine."""
    ip = get_local_ip()
    if ip == "127.0.0.1":
        return None
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24"


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    m = int(seconds // 60)
    s = seconds % 60
    return f"{m}m {s:.1f}s"


def port_range_count(port_spec: str) -> int:
    """Return approximate number of ports for a spec string, for display."""
    if port_spec.lower() == "all":
        return 65535
    if port_spec.lower() == "top1000":
        return 1000
    if port_spec.lower() == "top100":
        return 100
    count = 0
    for part in port_spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            count += int(b) - int(a) + 1
        else:
            count += 1
    return count
