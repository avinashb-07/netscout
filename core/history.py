"""
NetScout PRO — Scan History Manager
Persists scan results to disk in JSON format.
Provides load, save, list, and comparison utilities.
"""

import json
import os
import datetime
from typing import List, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path

from core.scanner import HostResult, PortResult, PortState


HISTORY_DIR = Path.home() / ".netscout" / "history"


@dataclass
class ScanRecord:
    scan_id: str
    timestamp: str
    target: str
    port_spec: str
    protocol: str
    elapsed_sec: float
    host_count: int
    up_count: int
    open_port_count: int
    findings_count: int
    results: List[HostResult] = field(default_factory=list)


def _ensure_dir():
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def _scan_id() -> str:
    now = datetime.datetime.now()
    return now.strftime("scan_%Y%m%d_%H%M%S")


def save_scan(record: ScanRecord) -> str:
    """Save a scan record to disk. Returns the file path."""
    _ensure_dir()
    path = HISTORY_DIR / f"{record.scan_id}.json"

    def host_to_dict(h: HostResult) -> dict:
        return {
            "ip": h.ip, "hostname": h.hostname, "is_up": h.is_up,
            "os_guess": h.os_guess, "ttl": h.ttl,
            "scan_time_sec": h.scan_time_sec, "mac_address": h.mac_address,
            "risk_score": getattr(h, "risk_score", 0.0),
            "risk_level": getattr(h, "risk_level", "NONE"),
            "ports": [{
                "port": p.port, "protocol": p.protocol,
                "state": p.state.value, "service": p.service,
                "banner": p.banner, "response_time_ms": p.response_time_ms,
            } for p in h.ports],
        }

    data = {
        "scan_id": record.scan_id,
        "timestamp": record.timestamp,
        "target": record.target,
        "port_spec": record.port_spec,
        "protocol": record.protocol,
        "elapsed_sec": record.elapsed_sec,
        "host_count": record.host_count,
        "up_count": record.up_count,
        "open_port_count": record.open_port_count,
        "findings_count": record.findings_count,
        "results": [host_to_dict(h) for h in record.results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return str(path)


def load_scan(scan_id: str) -> Optional[ScanRecord]:
    """Load a scan record by ID."""
    _ensure_dir()
    path = HISTORY_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _dict_to_record(data)


def list_scans(limit: int = 20) -> List[ScanRecord]:
    """List recent scans, newest first."""
    _ensure_dir()
    files = sorted(HISTORY_DIR.glob("scan_*.json"), reverse=True)[:limit]
    records = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # Load summary only (skip results for speed)
            rec = ScanRecord(
                scan_id=data["scan_id"],
                timestamp=data["timestamp"],
                target=data["target"],
                port_spec=data["port_spec"],
                protocol=data["protocol"],
                elapsed_sec=data["elapsed_sec"],
                host_count=data["host_count"],
                up_count=data["up_count"],
                open_port_count=data["open_port_count"],
                findings_count=data.get("findings_count", 0),
                results=[],
            )
            records.append(rec)
        except (json.JSONDecodeError, KeyError):
            continue
    return records


def delete_scan(scan_id: str) -> bool:
    """Delete a scan record. Returns True if deleted."""
    path = HISTORY_DIR / f"{scan_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def _dict_to_record(data: dict) -> ScanRecord:
    results = []
    for hd in data.get("results", []):
        ports = []
        for pd in hd.get("ports", []):
            try:
                state = PortState(pd["state"])
            except ValueError:
                state = PortState.CLOSED
            ports.append(PortResult(
                port=pd["port"], protocol=pd["protocol"],
                state=state, service=pd.get("service", ""),
                banner=pd.get("banner", ""),
                response_time_ms=pd.get("response_time_ms", 0.0),
            ))
        h = HostResult(
            ip=hd["ip"], hostname=hd.get("hostname", ""),
            is_up=hd.get("is_up", False), os_guess=hd.get("os_guess", ""),
            ttl=hd.get("ttl", 0), scan_time_sec=hd.get("scan_time_sec", 0.0),
            ports=ports,
        )
        h.risk_score = hd.get("risk_score", 0.0)
        h.risk_level = hd.get("risk_level", "NONE")
        results.append(h)

    return ScanRecord(
        scan_id=data["scan_id"],
        timestamp=data["timestamp"],
        target=data["target"],
        port_spec=data["port_spec"],
        protocol=data["protocol"],
        elapsed_sec=data["elapsed_sec"],
        host_count=data["host_count"],
        up_count=data["up_count"],
        open_port_count=data["open_port_count"],
        findings_count=data.get("findings_count", 0),
        results=results,
    )
