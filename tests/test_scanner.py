"""
NetScout — Unit Tests
Run with: python -m pytest tests/ -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scanner import (
    expand_targets,
    parse_ports,
    guess_os_from_ttl,
    _icmp_checksum,
    PortState,
    PortResult,
    HostResult,
    SERVICE_MAP,
    TOP_100_PORTS,
)
from reports.reporter import to_text, to_json, to_html
from utils.helpers import (
    is_valid_ip,
    is_private_ip,
    ip_to_int,
    format_duration,
    port_range_count,
    get_local_ip,
)


# ─── Target expansion ──────────────────────────────────────────────────────────

class TestExpandTargets(unittest.TestCase):

    def test_single_ip(self):
        result = expand_targets("192.168.1.1")
        self.assertEqual(result, ["192.168.1.1"])

    def test_cidr_24(self):
        result = expand_targets("192.168.1.0/24")
        self.assertEqual(len(result), 254)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.254", result)
        self.assertNotIn("192.168.1.0", result)   # network address
        self.assertNotIn("192.168.1.255", result)  # broadcast

    def test_cidr_30(self):
        result = expand_targets("10.0.0.0/30")
        self.assertEqual(len(result), 2)  # .1 and .2

    def test_ip_range(self):
        result = expand_targets("192.168.1.1-5")
        self.assertEqual(result, ["192.168.1.1","192.168.1.2","192.168.1.3","192.168.1.4","192.168.1.5"])

    def test_csv_targets(self):
        result = expand_targets("10.0.0.1,10.0.0.2,10.0.0.3")
        self.assertEqual(result, ["10.0.0.1","10.0.0.2","10.0.0.3"])

    def test_deduplication(self):
        result = expand_targets("192.168.1.1,192.168.1.1")
        self.assertEqual(result.count("192.168.1.1"), 1)

    def test_whitespace_tolerance(self):
        result = expand_targets(" 192.168.1.1 , 192.168.1.2 ")
        self.assertEqual(result, ["192.168.1.1","192.168.1.2"])

    def test_empty_string(self):
        result = expand_targets("")
        self.assertEqual(result, [])


# ─── Port parsing ──────────────────────────────────────────────────────────────

class TestParsePorts(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(parse_ports("80"), [80])

    def test_range(self):
        result = parse_ports("20-25")
        self.assertEqual(result, [20,21,22,23,24,25])

    def test_csv_ports(self):
        result = parse_ports("22,80,443")
        self.assertEqual(sorted(result), [22,80,443])

    def test_mixed(self):
        result = parse_ports("22,80-82,443")
        self.assertIn(22, result)
        self.assertIn(80, result)
        self.assertIn(81, result)
        self.assertIn(82, result)
        self.assertIn(443, result)

    def test_top100_keyword(self):
        result = parse_ports("top100")
        self.assertEqual(result, TOP_100_PORTS)
        self.assertGreater(len(result), 50)

    def test_top1000_keyword(self):
        result = parse_ports("top1000")
        self.assertGreaterEqual(len(result), 100)

    def test_deduplication(self):
        result = parse_ports("80,80,80")
        self.assertEqual(result.count(80), 1)

    def test_sorted_output(self):
        result = parse_ports("443,22,80")
        self.assertEqual(result, sorted(result))


# ─── OS fingerprinting ────────────────────────────────────────────────────────

class TestOSGuess(unittest.TestCase):

    def test_linux_ttl(self):
        self.assertIn("Linux", guess_os_from_ttl(64))
        self.assertIn("Linux", guess_os_from_ttl(60))

    def test_windows_ttl(self):
        self.assertIn("Windows", guess_os_from_ttl(128))
        self.assertIn("Windows", guess_os_from_ttl(120))

    def test_cisco_ttl(self):
        self.assertIn("Cisco", guess_os_from_ttl(255))
        self.assertIn("Cisco", guess_os_from_ttl(200))

    def test_zero_ttl(self):
        result = guess_os_from_ttl(0)
        self.assertEqual(result, "Unknown")

    def test_negative_ttl(self):
        result = guess_os_from_ttl(-1)
        self.assertEqual(result, "Unknown")


# ─── ICMP checksum ────────────────────────────────────────────────────────────

class TestICMPChecksum(unittest.TestCase):

    def test_returns_int(self):
        self.assertIsInstance(_icmp_checksum(b"\x08\x00\x00\x00\x01\x00\x01\x00"), int)

    def test_all_zeros(self):
        result = _icmp_checksum(b"\x00\x00\x00\x00")
        self.assertIsInstance(result, int)

    def test_consistency(self):
        data = b"\x08\x00\x00\x00\x01\x00\x01\x00" + b"NetScout"
        self.assertEqual(_icmp_checksum(data), _icmp_checksum(data))


# ─── PortState enum ──────────────────────────────────────────────────────────

class TestPortState(unittest.TestCase):

    def test_values(self):
        self.assertEqual(PortState.OPEN.value, "open")
        self.assertEqual(PortState.CLOSED.value, "closed")
        self.assertEqual(PortState.FILTERED.value, "filtered")
        self.assertEqual(PortState.OPEN_FILTERED.value, "open|filtered")


# ─── Service map ─────────────────────────────────────────────────────────────

class TestServiceMap(unittest.TestCase):

    def test_common_ports(self):
        self.assertEqual(SERVICE_MAP[22], "ssh")
        self.assertEqual(SERVICE_MAP[80], "http")
        self.assertEqual(SERVICE_MAP[443], "https")
        self.assertEqual(SERVICE_MAP[3306], "mysql")
        self.assertEqual(SERVICE_MAP[5432], "postgresql")
        self.assertEqual(SERVICE_MAP[6379], "redis")
        self.assertEqual(SERVICE_MAP[27017], "mongodb")

    def test_missing_port_returns_nothing(self):
        # Unknown port should not be in map
        self.assertNotIn(99999, SERVICE_MAP)


# ─── Reporters ────────────────────────────────────────────────────────────────

def _make_sample_results():
    return [
        HostResult(
            ip="10.0.0.1", hostname="gateway.local", is_up=True,
            os_guess="Linux/macOS (TTL≤64)", ttl=64, scan_time_sec=1.23,
            ports=[
                PortResult(22, "tcp", PortState.OPEN, "ssh", "SSH-2.0-OpenSSH_8.9", 12.4),
                PortResult(80, "tcp", PortState.OPEN, "http", "Apache/2.4", 8.1),
            ]
        ),
        HostResult(ip="10.0.0.2", hostname="", is_up=False, os_guess="", ttl=0, scan_time_sec=3.0, ports=[]),
    ]

def _make_meta():
    return {
        "timestamp": "2024-01-01 12:00:00",
        "targets": "10.0.0.0/24",
        "port_spec": "top100",
        "protocol": "tcp",
        "command": "netscout 10.0.0.0/24 -p top100",
        "total_time": "4.23s",
    }


class TestTextReporter(unittest.TestCase):

    def setUp(self):
        self.results = _make_sample_results()
        self.meta = _make_meta()
        self.output = to_text(self.results, self.meta)

    def test_returns_string(self):
        self.assertIsInstance(self.output, str)

    def test_contains_ips(self):
        self.assertIn("10.0.0.1", self.output)
        self.assertIn("10.0.0.2", self.output)

    def test_contains_hostname(self):
        self.assertIn("gateway.local", self.output)

    def test_contains_ports(self):
        self.assertIn("22", self.output)
        self.assertIn("80", self.output)

    def test_contains_services(self):
        self.assertIn("ssh", self.output)
        self.assertIn("http", self.output)

    def test_contains_summary(self):
        self.assertIn("Hosts up:", self.output)

    def test_up_down_shown(self):
        self.assertIn("UP", self.output)
        self.assertIn("DOWN", self.output)


class TestJSONReporter(unittest.TestCase):

    def setUp(self):
        import json
        self.results = _make_sample_results()
        self.meta = _make_meta()
        self.data = json.loads(to_json(self.results, self.meta))

    def test_structure(self):
        self.assertIn("meta", self.data)
        self.assertIn("hosts", self.data)

    def test_host_count(self):
        self.assertEqual(len(self.data["hosts"]), 2)

    def test_up_host_fields(self):
        h = next(x for x in self.data["hosts"] if x["ip"] == "10.0.0.1")
        self.assertTrue(h["is_up"])
        self.assertEqual(h["hostname"], "gateway.local")
        self.assertEqual(len(h["ports"]), 2)

    def test_down_host_fields(self):
        h = next(x for x in self.data["hosts"] if x["ip"] == "10.0.0.2")
        self.assertFalse(h["is_up"])
        self.assertEqual(h["ports"], [])

    def test_port_fields(self):
        h = next(x for x in self.data["hosts"] if x["ip"] == "10.0.0.1")
        p = h["ports"][0]
        self.assertIn("port", p)
        self.assertIn("state", p)
        self.assertIn("service", p)
        self.assertIn("response_time_ms", p)

    def test_meta_fields(self):
        self.assertEqual(self.data["meta"]["targets"], "10.0.0.0/24")
        self.assertEqual(self.data["meta"]["protocol"], "tcp")


class TestHTMLReporter(unittest.TestCase):

    def setUp(self):
        self.results = _make_sample_results()
        self.meta = _make_meta()
        self.html = to_html(self.results, self.meta)

    def test_returns_string(self):
        self.assertIsInstance(self.html, str)

    def test_valid_html_structure(self):
        self.assertIn("<!DOCTYPE html>", self.html)
        self.assertIn("</html>", self.html)

    def test_contains_ips(self):
        self.assertIn("10.0.0.1", self.html)
        self.assertIn("10.0.0.2", self.html)

    def test_contains_port_data(self):
        self.assertIn("22", self.html)
        self.assertIn("ssh", self.html)

    def test_no_xss_in_banner(self):
        # Verify < and > in banners are escaped
        from core.scanner import PortResult, PortState, HostResult
        r = [HostResult(
            ip="1.2.3.4", hostname="", is_up=True, os_guess="", ttl=64, scan_time_sec=1.0,
            ports=[PortResult(80, "tcp", PortState.OPEN, "http", "<script>alert(1)</script>", 5.0)]
        )]
        html = to_html(r, self.meta)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


# ─── Utils ────────────────────────────────────────────────────────────────────

class TestHelpers(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("10.0.0.1"))
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertTrue(is_valid_ip("255.255.255.255"))

    def test_invalid_ip(self):
        self.assertFalse(is_valid_ip("999.1.1.1"))
        self.assertFalse(is_valid_ip("not-an-ip"))
        self.assertFalse(is_valid_ip("192.168.1"))
        self.assertFalse(is_valid_ip(""))

    def test_private_ip(self):
        self.assertTrue(is_private_ip("192.168.0.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.0.1"))

    def test_public_ip(self):
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))

    def test_ip_to_int(self):
        self.assertEqual(ip_to_int("0.0.0.0"), 0)
        self.assertEqual(ip_to_int("0.0.0.1"), 1)
        self.assertEqual(ip_to_int("0.0.1.0"), 256)
        self.assertEqual(ip_to_int("255.255.255.255"), 4294967295)

    def test_format_duration_seconds(self):
        self.assertEqual(format_duration(5.5), "5.50s")
        self.assertEqual(format_duration(0.1), "0.10s")

    def test_format_duration_minutes(self):
        result = format_duration(90.0)
        self.assertIn("m", result)

    def test_port_range_count_all(self):
        self.assertEqual(port_range_count("all"), 65535)

    def test_port_range_count_top100(self):
        self.assertEqual(port_range_count("top100"), 100)

    def test_port_range_count_range(self):
        self.assertEqual(port_range_count("1-100"), 100)

    def test_port_range_count_csv(self):
        self.assertEqual(port_range_count("22,80,443"), 3)

    def test_get_local_ip_returns_string(self):
        ip = get_local_ip()
        self.assertIsInstance(ip, str)
        self.assertGreater(len(ip), 0)


# ─── DataClass integrity ──────────────────────────────────────────────────────

class TestDataClasses(unittest.TestCase):

    def test_port_result_defaults(self):
        p = PortResult(port=80, protocol="tcp", state=PortState.OPEN)
        self.assertEqual(p.service, "")
        self.assertEqual(p.banner, "")
        self.assertEqual(p.response_time_ms, 0.0)

    def test_host_result_defaults(self):
        h = HostResult(ip="1.2.3.4")
        self.assertEqual(h.hostname, "")
        self.assertFalse(h.is_up)
        self.assertEqual(h.ports, [])
        self.assertEqual(h.ttl, 0)

    def test_host_result_port_list_isolation(self):
        # Mutable default args must NOT be shared between instances
        h1 = HostResult(ip="1.2.3.4")
        h2 = HostResult(ip="5.6.7.8")
        h1.ports.append(PortResult(22, "tcp", PortState.OPEN))
        self.assertEqual(len(h2.ports), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
