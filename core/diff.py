"""
NetScout PRO — Scan Diff Engine
Compare two scan results and surface changes: new hosts, gone hosts,
opened/closed ports, risk score changes.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from core.scanner import HostResult


@dataclass
class PortChange:
    port: int
    protocol: str
    service: str
    change: str          # "opened" | "closed"


@dataclass
class HostDiff:
    ip: str
    hostname: str
    status_change: Optional[str]   # "came_up" | "went_down" | None
    port_changes: List[PortChange] = field(default_factory=list)
    risk_before: float = 0.0
    risk_after: float = 0.0
    risk_delta: float = 0.0
    is_new_host: bool = False
    is_gone_host: bool = False

    @property
    def has_changes(self) -> bool:
        return bool(self.status_change or self.port_changes
                    or self.is_new_host or self.is_gone_host
                    or abs(self.risk_delta) > 0.5)


def diff_scans(scan_a: List[HostResult], scan_b: List[HostResult]) -> List[HostDiff]:
    """
    Compare scan_a (older) against scan_b (newer).
    Returns list of HostDiff for every host that changed.
    """
    map_a = {h.ip: h for h in scan_a}
    map_b = {h.ip: h for h in scan_b}
    all_ips = sorted(set(map_a) | set(map_b))

    results = []

    for ip in all_ips:
        ha = map_a.get(ip)
        hb = map_b.get(ip)

        diff = HostDiff(
            ip=ip,
            hostname=(hb or ha).hostname,
            status_change=None,
            risk_before=getattr(ha, "risk_score", 0.0) if ha else 0.0,
            risk_after=getattr(hb, "risk_score", 0.0) if hb else 0.0,
        )
        diff.risk_delta = round(diff.risk_after - diff.risk_before, 1)

        # New host
        if ha is None:
            diff.is_new_host = True
            diff.status_change = "came_up" if hb.is_up else None
            for p in (hb.ports if hb else []):
                diff.port_changes.append(PortChange(p.port, p.protocol, p.service, "opened"))
            results.append(diff)
            continue

        # Gone host
        if hb is None:
            diff.is_gone_host = True
            diff.status_change = "went_down" if ha.is_up else None
            for p in ha.ports:
                diff.port_changes.append(PortChange(p.port, p.protocol, p.service, "closed"))
            results.append(diff)
            continue

        # Status change
        if ha.is_up != hb.is_up:
            diff.status_change = "came_up" if hb.is_up else "went_down"

        # Port changes (only meaningful if both are up)
        if ha.is_up or hb.is_up:
            ports_a = {p.port: p for p in ha.ports}
            ports_b = {p.port: p for p in hb.ports}

            for port, p in ports_b.items():
                if port not in ports_a:
                    diff.port_changes.append(PortChange(port, p.protocol, p.service, "opened"))

            for port, p in ports_a.items():
                if port not in ports_b:
                    diff.port_changes.append(PortChange(port, p.protocol, p.service, "closed"))

        if diff.has_changes:
            results.append(diff)

    return results


def format_diff_text(diffs: List[HostDiff]) -> str:
    """Plain-text representation of a diff result."""
    if not diffs:
        return "No changes detected between the two scans."

    lines = ["SCAN DIFF REPORT", "=" * 50]
    for d in diffs:
        label = ""
        if d.is_new_host:
            label = "[NEW HOST]"
        elif d.is_gone_host:
            label = "[GONE]"
        elif d.status_change == "came_up":
            label = "[CAME UP]"
        elif d.status_change == "went_down":
            label = "[WENT DOWN]"
        else:
            label = "[CHANGED]"

        lines.append(f"\n{label} {d.ip}{' (' + d.hostname + ')' if d.hostname else ''}")

        if abs(d.risk_delta) > 0.5:
            arrow = "↑" if d.risk_delta > 0 else "↓"
            lines.append(f"  Risk: {d.risk_before} → {d.risk_after} ({arrow}{abs(d.risk_delta):.1f})")

        for pc in sorted(d.port_changes, key=lambda x: x.port):
            sym = "+" if pc.change == "opened" else "-"
            lines.append(f"  {sym} port {pc.port}/{pc.protocol} ({pc.service}) {pc.change}")

    lines.append(f"\n{'=' * 50}")
    lines.append(f"Total changed hosts: {len(diffs)}")
    opened = sum(len([c for c in d.port_changes if c.change == "opened"]) for d in diffs)
    closed = sum(len([c for c in d.port_changes if c.change == "closed"]) for d in diffs)
    lines.append(f"Ports opened: {opened}  |  Ports closed: {closed}")
    return "\n".join(lines)
