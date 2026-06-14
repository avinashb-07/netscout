"""
NetScout — XML Reporter
Produces industry-standard XML output importable into Metasploit, security dashboards, and SIEM platforms.
"""

import xml.etree.ElementTree as ET
import xml.dom.minidom
import time
from typing import List

try:
    from core.scanner import HostResult, PortState
except ImportError:
    from scanner import HostResult, PortState  # type: ignore


def to_xml(results: List[HostResult], scan_meta: dict) -> str:
    """Generate structured XML scan report."""
    root = ET.Element("netscoutrun")
    root.set("scanner", "netscout")
    root.set("version", "1.0")
    root.set("args", scan_meta.get("command", "netscout"))
    root.set("start", str(int(time.time())))
    root.set("startstr", scan_meta.get("timestamp", ""))
    root.set("xmloutputversion", "1.04")

    # scaninfo
    si = ET.SubElement(root, "scaninfo")
    si.set("type", "connect" if scan_meta.get("protocol") == "tcp" else "udp")
    si.set("protocol", scan_meta.get("protocol", "tcp"))
    si.set("numservices", str(sum(len(h.ports) for h in results)))
    si.set("services", scan_meta.get("port_spec", ""))

    # verbosity fields
    ET.SubElement(root, "verbose").set("level", "0")
    ET.SubElement(root, "debugging").set("level", "0")

    for host in results:
        h_el = ET.SubElement(root, "host")
        h_el.set("starttime", str(int(time.time())))
        h_el.set("endtime", str(int(time.time() + host.scan_time_sec)))

        # status
        st = ET.SubElement(h_el, "status")
        st.set("state", "up" if host.is_up else "down")
        st.set("reason", "echo-reply" if host.is_up else "no-response")
        st.set("reason_ttl", str(host.ttl))

        # address
        addr = ET.SubElement(h_el, "address")
        addr.set("addr", host.ip)
        addr.set("addrtype", "ipv4")

        # hostnames
        hostnames_el = ET.SubElement(h_el, "hostnames")
        if host.hostname:
            hn = ET.SubElement(hostnames_el, "hostname")
            hn.set("name", host.hostname)
            hn.set("type", "PTR")

        # ports
        if host.is_up and host.ports:
            ports_el = ET.SubElement(h_el, "ports")
            for p in host.ports:
                port_el = ET.SubElement(ports_el, "port")
                port_el.set("protocol", p.protocol)
                port_el.set("portid", str(p.port))

                state_el = ET.SubElement(port_el, "state")
                state_el.set("state", p.state.value)
                state_el.set("reason", "syn-ack" if p.state == PortState.OPEN else "no-response")
                state_el.set("reason_ttl", str(host.ttl))

                svc_el = ET.SubElement(port_el, "service")
                svc_el.set("name", p.service or "unknown")
                if p.banner:
                    svc_el.set("product", p.banner[:100])

                if p.banner:
                    script_el = ET.SubElement(port_el, "script")
                    script_el.set("id", "banner")
                    script_el.set("output", p.banner[:200])

        # os
        if host.is_up and host.os_guess:
            os_el = ET.SubElement(h_el, "os")
            osmatch = ET.SubElement(os_el, "osmatch")
            osmatch.set("name", host.os_guess)
            osmatch.set("accuracy", "70")
            osmatch.set("line", "1")

        # times
        times_el = ET.SubElement(h_el, "times")
        times_el.set("srtt", str(int(host.scan_time_sec * 1000000)))
        times_el.set("rttvar", "50000")
        times_el.set("to", "1000000")

    # runstats
    rs = ET.SubElement(root, "runstats")
    fin = ET.SubElement(rs, "finished")
    fin.set("time", str(int(time.time())))
    fin.set("timestr", scan_meta.get("timestamp", ""))
    fin.set("elapsed", scan_meta.get("total_time", "0s").replace("s", ""))
    fin.set("summary", f"NetScout scan report")
    fin.set("exit", "success")
    hosts_el = ET.SubElement(rs, "hosts")
    up = sum(1 for h in results if h.is_up)
    hosts_el.set("up", str(up))
    hosts_el.set("down", str(len(results) - up))
    hosts_el.set("total", str(len(results)))

    # Pretty print
    raw = ET.tostring(root, encoding="unicode")
    parsed = xml.dom.minidom.parseString(raw)
    return parsed.toprettyxml(indent="  ", encoding=None)
