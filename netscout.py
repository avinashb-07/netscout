#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          NetScout PRO v2.0 — Network Intelligence Platform       ║
║          Pure Python · Zero external dependencies         ║
║          Educational use only — scan only what you own           ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import time
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import Scanner, expand_targets, parse_ports, HostResult
from core.vulndb import VULNDB, score_host, findings_for_host
from core.diff import diff_scans, format_diff_text
from core.history import ScanRecord, save_scan, load_scan, list_scans, delete_scan, _scan_id
from reports.reporter import to_text, to_json, save_report
from reports.xml_reporter import to_xml
from reports.html_pro import to_html_pro

# ── ANSI ──────────────────────────────────────────────────────────────────────
R="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
CY="\033[96m"; GR="\033[92m"; RD="\033[91m"; AM="\033[93m"; PU="\033[95m"; BL="\033[94m"
def c(t,col): return f"{col}{t}{R}"
def head(t):  return f"\n{BOLD}{CY}{t}{R}"

BANNER = f"""{CY}{BOLD}
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗  ██████╗ ██████╗  ██████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝ ██╔══██╗██╔══██╗██╔═══██╗
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██║   ██║   ██║    ██████╔╝██████╔╝██║   ██║
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██║   ██║   ██║    ██╔═══╝ ██╔══██╗██║   ██║
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║    ██║     ██║  ██║╚██████╔╝
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝   ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝{R}
{DIM}  v2.0 PRO  ·  Network Intelligence Platform  ·  Educational Use Only{R}
"""


# ── Severity colours ──────────────────────────────────────────────────────────
SEV_COL = {"CRIT": RD, "HIGH": AM, "MED": PU, "LOW": BL, "NONE": DIM}

def sev_badge(level: str) -> str:
    col = SEV_COL.get(level, DIM)
    return f"{col}{BOLD}[{level:4}]{R}"


# ── Print helpers ─────────────────────────────────────────────────────────────
def print_host(host: HostResult, show_banners: bool = True, show_vulns: bool = True):
    status = c("UP  ", GR) if host.is_up else c("DOWN", DIM)
    hostname = f" {DIM}({host.hostname}){R}" if host.hostname else ""
    risk_score = getattr(host, "risk_score", 0.0)
    risk_level = getattr(host, "risk_level", "NONE")
    risk_str = ""
    if host.is_up and risk_level != "NONE":
        risk_str = f"  {sev_badge(risk_level)} {SEV_COL[risk_level]}{risk_score}/10{R}"

    print(f"\n{BOLD}{c(host.ip, CY)}{hostname}{R}  [{status}]{risk_str}")

    if not host.is_up:
        return

    print(f"  {DIM}OS: {host.os_guess or '?'}  TTL: {host.ttl}  Scan: {host.scan_time_sec:.2f}s{R}")

    if host.ports:
        print(f"\n  {DIM}{'PORT':<9} {'PROTO':<6} {'STATE':<10} {'SERVICE':<20} {'RISK':<6}  BANNER{R}")
        print(f"  {DIM}{'─'*72}{R}")
        for p in host.ports:
            vuln = VULNDB.get(p.port)
            risk_col = SEV_COL.get(vuln.severity if vuln else "NONE", DIM)
            risk_txt = vuln.severity if vuln else "—"
            banner = ""
            if show_banners and p.banner:
                banner = p.banner.replace("\n", " ")[:45]
                if len(p.banner) > 45:
                    banner += "…"
            print(
                f"  {c(str(p.port)+'/',CY)}{DIM}{p.protocol:<5}{R}  "
                f"{c(p.state.value, GR):<10}  {c(p.service, AM):<20}  "
                f"{risk_col}{risk_txt:<6}{R}  {DIM}{banner}{R}"
            )

        if show_vulns:
            findings = findings_for_host(host.ports)
            if findings:
                print(f"\n  {BOLD}Findings:{R}")
                for port_result, vuln in findings:
                    print(f"    {sev_badge(vuln.severity)}  {c(str(port_result.port)+'/'+port_result.service, CY)}  {vuln.title}")
                    print(f"             {DIM}{', '.join(vuln.cves)}{R}")
                    print(f"             {GR}→ {vuln.recommendation}{R}")
    else:
        print(f"  {DIM}No open ports in scanned range.{R}")


def print_summary(results: list, total_time: float):
    up = [h for h in results if h.is_up]
    total_open = sum(len(h.ports) for h in up)
    all_findings = []
    for h in up:
        for p, v in findings_for_host(h.ports):
            all_findings.append((h, p, v))
    crit = sum(1 for _, _, v in all_findings if v.severity == "CRIT")
    high = sum(1 for _, _, v in all_findings if v.severity == "HIGH")

    print(f"\n{BOLD}{CY}{'═'*60}{R}")
    print(f"  {BOLD}SCAN COMPLETE{R}  {DIM}in {total_time:.2f}s{R}")
    print(f"  Hosts  : {c(str(len(up))+' up', GR)} / {DIM}{len(results)-len(up)} down{R} / {len(results)} total")
    print(f"  Ports  : {c(str(total_open)+' open', CY)}")
    print(f"  Findings: {c(str(crit)+' CRIT', RD)}  {c(str(high)+' HIGH', AM)}  {DIM}{len(all_findings)-crit-high} other{R}")
    print(f"{BOLD}{CY}{'═'*60}{R}\n")


# ── Subcommand: scan ──────────────────────────────────────────────────────────
def cmd_scan(args):
    print(BANNER)
    protocol = "udp" if args.udp else "tcp"

    # Resolve
    print(f"{DIM}[*] Resolving targets…{R}", end=" ", flush=True)
    targets = expand_targets(args.targets)
    if not targets:
        print(f"\n{RD}[!] No valid targets found.{R}")
        sys.exit(1)
    print(f"{GR}{len(targets)} host(s){R}")

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"{RD}[!] Invalid port spec: {e}{R}")
        sys.exit(1)
    print(f"{DIM}[*] Ports: '{args.ports}' → {len(ports)} port(s){R}")
    print(f"{DIM}[*] Protocol: {protocol.upper()}  Threads: {args.threads}  Timeout: {args.timeout}s{R}")
    print(f"{DIM}[*] Banner grabbing: {'on' if not args.no_banner else 'off'}  "
          f"Risk scoring: on  Vuln correlation: on{R}\n")

    cmd_str = (f"netscout scan {args.targets} -p {args.ports}"
               + (" --udp" if args.udp else "")
               + (f" -t {args.threads}" if args.threads != 150 else "")
               + (f" --timeout {args.timeout}" if args.timeout != 1.0 else ""))

    scanner = Scanner(
        targets=targets, ports=ports, protocol=protocol,
        threads=args.threads, timeout=args.timeout,
        grab_banners=not args.no_banner,
        skip_ping=args.skip_ping, verbose=args.verbose,
    )

    results = []
    t0 = time.time()

    for ip in targets:
        print(f"{DIM}[→] {ip}…{R}", end="\r", flush=True)
        host = scanner._scan_host(ip)
        # Attach risk scoring
        rs, rl = score_host(host.ports)
        host.risk_score = rs
        host.risk_level = rl
        results.append(host)
        print_host(host, show_banners=not args.no_banner, show_vulns=not args.no_vulns)

    total_time = time.time() - t0
    print_summary(results, total_time)

    # Save to history
    all_findings = []
    for h in results:
        if h.is_up:
            all_findings.extend(findings_for_host(h.ports))

    record = ScanRecord(
        scan_id=_scan_id(),
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=args.targets,
        port_spec=args.ports,
        protocol=protocol,
        elapsed_sec=round(total_time, 2),
        host_count=len(results),
        up_count=sum(1 for h in results if h.is_up),
        open_port_count=sum(len(h.ports) for h in results),
        findings_count=len(all_findings),
        results=results,
    )
    saved_path = save_scan(record)
    print(f"{DIM}[✓] Scan saved to history: {record.scan_id}{R}")

    # Output reports
    if args.output:
        meta = {
            "timestamp": record.timestamp,
            "targets": args.targets,
            "port_spec": args.ports,
            "protocol": protocol,
            "command": cmd_str,
            "total_time": f"{total_time:.2f}s",
        }
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".html":
            content = to_html_pro(results, meta)
        elif ext == ".json":
            content = to_json(results, meta)
        elif ext == ".xml":
            content = to_xml(results, meta)
        else:
            content = to_text(results, meta)
        save_report(content, args.output)
        print(f"{GR}[✓] Report saved: {args.output}{R}\n")


# ── Subcommand: history ───────────────────────────────────────────────────────
def cmd_history(args):
    scans = list_scans(limit=20)
    if not scans:
        print(f"{DIM}No scan history found. Run 'netscout scan <target>' first.{R}")
        return

    print(head("Scan History"))
    print(f"\n  {'ID':<25} {'TARGET':<22} {'DATE':<20} {'UP':>4} {'PORTS':>6} {'VULNS':>6}")
    print(f"  {'─'*85}")
    for s in scans:
        print(f"  {c(s.scan_id, CY):<35} {s.target:<22} {s.timestamp:<20} "
              f"{c(str(s.up_count), GR):>12} {AM}{s.open_port_count:>6}{R} {RD}{s.findings_count:>6}{R}")


# ── Subcommand: diff ──────────────────────────────────────────────────────────
def cmd_diff(args):
    a = load_scan(args.scan_a)
    b = load_scan(args.scan_b)
    if not a:
        print(f"{RD}[!] Scan not found: {args.scan_a}{R}")
        sys.exit(1)
    if not b:
        print(f"{RD}[!] Scan not found: {args.scan_b}{R}")
        sys.exit(1)

    print(head(f"Scan Diff: {args.scan_a}  →  {args.scan_b}"))
    diffs = diff_scans(a.results, b.results)

    if not diffs:
        print(f"\n{GR}  No changes detected between the two scans.{R}\n")
        return

    for d in diffs:
        label = ""
        if d.is_new_host:
            label = c("[NEW HOST]", GR)
        elif d.is_gone_host:
            label = c("[GONE]", DIM)
        elif d.status_change == "came_up":
            label = c("[CAME UP]", GR)
        elif d.status_change == "went_down":
            label = c("[WENT DOWN]", RD)
        else:
            label = c("[CHANGED]", AM)

        print(f"\n  {label} {BOLD}{c(d.ip, CY)}{R}"
              f"{DIM}{'  ('+d.hostname+')' if d.hostname else ''}{R}")

        if abs(d.risk_delta) > 0.5:
            arrow = c(f"↑ +{d.risk_delta:.1f}", RD) if d.risk_delta > 0 else c(f"↓ {d.risk_delta:.1f}", GR)
            print(f"       Risk: {d.risk_before} → {d.risk_after}  ({arrow})")

        for pc in sorted(d.port_changes, key=lambda x: x.port):
            sym = c("+", GR) if pc.change == "opened" else c("-", RD)
            print(f"       {sym} port {c(str(pc.port), CY)}/{pc.protocol} ({AM}{pc.service}{R}) {pc.change}")

    print(f"\n  {DIM}Total changed: {len(diffs)} host(s){R}\n")


# ── Subcommand: show ──────────────────────────────────────────────────────────
def cmd_show(args):
    rec = load_scan(args.scan_id)
    if not rec:
        print(f"{RD}[!] Scan not found: {args.scan_id}{R}")
        sys.exit(1)

    print(head(f"Scan: {rec.scan_id}"))
    print(f"{DIM}  Target: {rec.target}  |  Ports: {rec.port_spec}  |  {rec.timestamp}  |  {rec.elapsed_sec}s{R}\n")

    for host in rec.results:
        print_host(host, show_banners=True, show_vulns=True)

    print_summary(rec.results, rec.elapsed_sec)


# ── Subcommand: delete ────────────────────────────────────────────────────────
def cmd_delete(args):
    if delete_scan(args.scan_id):
        print(f"{GR}[✓] Deleted: {args.scan_id}{R}")
    else:
        print(f"{RD}[!] Not found: {args.scan_id}{R}")


# ── Argument parser ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscout",
        description="NetScout PRO — Network Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  scan     Run a network scan
  history  List past scans
  show     Display a past scan by ID
  diff     Compare two past scans
  delete   Delete a scan from history

Examples:
  python netscout.py scan 192.168.1.1
  python netscout.py scan 192.168.1.0/24 -p top100 -o report.html
  python netscout.py scan 10.0.0.1-20 -p 22,80,443,3306 --threads 200
  python netscout.py scan testphp.vulnweb.com -p 1-1024 --udp
  python netscout.py history
  python netscout.py diff scan_20240101_120000 scan_20240102_090000
  python netscout.py show scan_20240101_120000
        """,
    )
    sub = parser.add_subparsers(dest="command")

    # ── scan ──
    sp = sub.add_parser("scan", help="Run a network scan")
    sp.add_argument("targets", help="IP, CIDR, range, hostname, or comma-separated list")
    sp.add_argument("-p","--ports", default="top100", metavar="PORTS",
                    help="Ports: top20/top100/top1000/all/range/csv (default: top100)")
    sp.add_argument("--udp", action="store_true", help="UDP scan instead of TCP")
    sp.add_argument("-t","--threads", type=int, default=150, metavar="N")
    sp.add_argument("--timeout", type=float, default=1.0, metavar="SEC")
    sp.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")
    sp.add_argument("--no-vulns", action="store_true", help="Skip vulnerability correlation output")
    sp.add_argument("--skip-ping", action="store_true", help="Treat all hosts as up")
    sp.add_argument("-o","--output", metavar="FILE", help="Report file (.html .json .xml .txt)")
    sp.add_argument("-v","--verbose", action="store_true")

    # ── history ──
    sub.add_parser("history", help="List past scans")

    # ── show ──
    sh = sub.add_parser("show", help="Show a past scan")
    sh.add_argument("scan_id", help="Scan ID from history")

    # ── diff ──
    df = sub.add_parser("diff", help="Compare two scans")
    df.add_argument("scan_a", help="Older scan ID")
    df.add_argument("scan_b", help="Newer scan ID")

    # ── delete ──
    dl = sub.add_parser("delete", help="Delete a scan from history")
    dl.add_argument("scan_id")

    return parser


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    dispatch = {
        "scan":    cmd_scan,
        "history": cmd_history,
        "show":    cmd_show,
        "diff":    cmd_diff,
        "delete":  cmd_delete,
    }
    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
