"""
NetScout - Report Generator
Outputs scan results as HTML, JSON, or plain text.
"""

import json
import datetime
from typing import List
from pathlib import Path

# Import carefully to allow standalone use
try:
    from core.scanner import HostResult, PortState
except ImportError:
    from scanner import HostResult, PortState  # type: ignore


# ─── JSON ─────────────────────────────────────────────────────────────────────

def to_json(results: List[HostResult], scan_meta: dict) -> str:
    data = {
        "meta": scan_meta,
        "hosts": [],
    }
    for h in results:
        host_dict = {
            "ip": h.ip,
            "hostname": h.hostname,
            "is_up": h.is_up,
            "os_guess": h.os_guess,
            "ttl": h.ttl,
            "scan_time_sec": round(h.scan_time_sec, 3),
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state.value,
                    "service": p.service,
                    "banner": p.banner,
                    "response_time_ms": round(p.response_time_ms, 2),
                }
                for p in h.ports
            ],
        }
        data["hosts"].append(host_dict)
    return json.dumps(data, indent=2)


# ─── Plain Text ───────────────────────────────────────────────────────────────

def to_text(results: List[HostResult], scan_meta: dict) -> str:
    lines = []
    lines.append("=" * 65)
    lines.append(f"  NetScout — Network Scan Report")
    lines.append(f"  Generated : {scan_meta.get('timestamp', 'N/A')}")
    lines.append(f"  Targets   : {scan_meta.get('targets', 'N/A')}")
    lines.append(f"  Ports     : {scan_meta.get('port_spec', 'N/A')}")
    lines.append(f"  Protocol  : {scan_meta.get('protocol', 'tcp').upper()}")
    lines.append("=" * 65)

    for h in results:
        lines.append(f"\nHost: {h.ip}" + (f" ({h.hostname})" if h.hostname else ""))
        lines.append(f"  Status  : {'UP' if h.is_up else 'DOWN'}")
        if h.is_up:
            lines.append(f"  OS Guess: {h.os_guess}")
            lines.append(f"  TTL     : {h.ttl}")
            lines.append(f"  Scan    : {h.scan_time_sec:.2f}s")
            if h.ports:
                lines.append(f"\n  {'PORT':<10} {'PROTO':<6} {'STATE':<16} {'SERVICE':<20} BANNER")
                lines.append("  " + "-" * 60)
                for p in h.ports:
                    banner_short = (p.banner[:30] + "…") if len(p.banner) > 30 else p.banner
                    banner_short = banner_short.replace("\n", " ").replace("\r", "")
                    lines.append(
                        f"  {p.port:<10} {p.protocol:<6} {p.state.value:<16} {p.service:<20} {banner_short}"
                    )
            else:
                lines.append("  No open ports found.")
    lines.append("\n" + "=" * 65)
    up = sum(1 for h in results if h.is_up)
    total_ports = sum(len(h.ports) for h in results)
    lines.append(f"  Hosts up: {up}/{len(results)}   Open ports: {total_ports}")
    lines.append("=" * 65)
    return "\n".join(lines)


# ─── HTML ─────────────────────────────────────────────────────────────────────

def to_html(results: List[HostResult], scan_meta: dict) -> str:
    ts = scan_meta.get("timestamp", "N/A")
    target_str = scan_meta.get("targets", "N/A")
    port_spec = scan_meta.get("port_spec", "N/A")
    protocol = scan_meta.get("protocol", "tcp").upper()
    cmd = scan_meta.get("command", "netscout")

    up_count = sum(1 for h in results if h.is_up)
    total_open = sum(len(h.ports) for h in results)

    host_cards = ""
    for h in results:
        status_cls = "up" if h.is_up else "down"
        status_label = "UP" if h.is_up else "DOWN"
        hostname_html = f'<span class="hostname">({h.hostname})</span>' if h.hostname else ""

        if h.is_up and h.ports:
            rows = ""
            for p in h.ports:
                state_cls = "open" if p.state.value == "open" else "filtered"
                banner_esc = p.banner.replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")
                banner_short = (banner_esc[:80] + "…") if len(banner_esc) > 80 else banner_esc
                rows += f"""
                <tr>
                  <td class="port-num">{p.port}</td>
                  <td>{p.protocol.upper()}</td>
                  <td><span class="state-badge {state_cls}">{p.state.value}</span></td>
                  <td class="service-name">{p.service}</td>
                  <td class="rtt">{p.response_time_ms:.1f} ms</td>
                  <td class="banner-cell" title="{banner_esc}">{banner_short or "—"}</td>
                </tr>"""
            port_table = f"""
            <div class="port-table-wrap">
              <table class="port-table">
                <thead>
                  <tr>
                    <th>Port</th><th>Proto</th><th>State</th>
                    <th>Service</th><th>RTT</th><th>Banner</th>
                  </tr>
                </thead>
                <tbody>{rows}</tbody>
              </table>
            </div>"""
        elif h.is_up:
            port_table = '<p class="no-ports">No open ports detected in scan range.</p>'
        else:
            port_table = '<p class="no-ports">Host is down or not responding.</p>'

        os_row = f'<span class="tag">{h.os_guess}</span>' if h.os_guess and h.is_up else ""
        ttl_row = f'<span class="tag tag-dim">TTL {h.ttl}</span>' if h.ttl and h.is_up else ""
        time_row = f'<span class="tag tag-dim">{h.scan_time_sec:.2f}s</span>' if h.is_up else ""

        host_cards += f"""
        <div class="host-card {status_cls}">
          <div class="host-header">
            <div class="host-identity">
              <span class="status-dot {status_cls}"></span>
              <span class="ip">{h.ip}</span>
              {hostname_html}
            </div>
            <div class="host-tags">
              <span class="badge {status_cls}">{status_label}</span>
              {os_row}{ttl_row}{time_row}
              <span class="tag tag-ports">{len(h.ports)} open port{'s' if len(h.ports) != 1 else ''}</span>
            </div>
          </div>
          {port_table}
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetScout Report — {target_str}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600&display=swap');

    :root {{
      --bg:       #0d1117;
      --surface:  #161b22;
      --border:   #21262d;
      --border2:  #30363d;
      --text:     #e6edf3;
      --muted:    #8b949e;
      --accent:   #58a6ff;
      --green:    #3fb950;
      --red:      #f85149;
      --orange:   #d29922;
      --purple:   #bc8cff;
      --mono:     'JetBrains Mono', monospace;
      --sans:     'Inter', system-ui, sans-serif;
    }}

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      line-height: 1.6;
      padding: 0 0 60px;
    }}

    /* ── Header ── */
    .top-bar {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 20px 32px;
      display: flex;
      align-items: center;
      gap: 16px;
    }}
    .logo-mark {{
      width: 36px; height: 36px;
      background: linear-gradient(135deg, var(--accent), #6e40c9);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-family: var(--mono); font-weight: 600; font-size: 16px;
      color: #fff; flex-shrink: 0;
    }}
    .top-bar h1 {{
      font-size: 18px; font-weight: 600;
      letter-spacing: -.3px;
    }}
    .top-bar h1 span {{ color: var(--accent); }}
    .top-bar .subtitle {{ color: var(--muted); font-size: 12px; margin-top: 1px; }}

    /* ── Stats bar ── */
    .stats-bar {{
      display: flex; gap: 0;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }}
    .stat-item {{
      padding: 14px 24px;
      border-right: 1px solid var(--border);
    }}
    .stat-item:last-child {{ border-right: none; }}
    .stat-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; }}
    .stat-value {{ font-size: 22px; font-weight: 600; font-family: var(--mono); margin-top: 2px; }}
    .stat-value.green {{ color: var(--green); }}
    .stat-value.accent {{ color: var(--accent); }}
    .stat-value.orange {{ color: var(--orange); }}

    /* ── Scan meta ── */
    .scan-meta {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin: 24px 32px 0;
      padding: 14px 20px;
      font-family: var(--mono);
      font-size: 12px;
      color: var(--muted);
    }}
    .scan-meta strong {{ color: var(--text); }}
    .scan-meta .cmd {{ color: var(--accent); }}

    /* ── Host cards ── */
    .hosts-container {{ padding: 24px 32px 0; display: flex; flex-direction: column; gap: 16px; }}

    .host-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      transition: border-color .15s;
    }}
    .host-card.up {{ border-left: 3px solid var(--green); }}
    .host-card.down {{ border-left: 3px solid var(--border2); opacity: .65; }}
    .host-card:hover {{ border-color: var(--border2); }}

    .host-header {{
      display: flex; justify-content: space-between; align-items: center;
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      flex-wrap: wrap; gap: 10px;
    }}
    .host-identity {{ display: flex; align-items: center; gap: 10px; }}
    .status-dot {{
      width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
    }}
    .status-dot.up {{ background: var(--green); box-shadow: 0 0 6px var(--green); }}
    .status-dot.down {{ background: var(--muted); }}
    .ip {{ font-family: var(--mono); font-size: 15px; font-weight: 600; color: var(--text); }}
    .hostname {{ font-size: 12px; color: var(--muted); }}

    .host-tags {{ display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }}
    .badge {{
      padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;
      text-transform: uppercase; letter-spacing: .5px;
    }}
    .badge.up {{ background: rgba(63,185,80,.15); color: var(--green); border: 1px solid rgba(63,185,80,.3); }}
    .badge.down {{ background: rgba(139,148,158,.1); color: var(--muted); border: 1px solid var(--border2); }}
    .tag {{
      padding: 2px 8px; border-radius: 4px; font-size: 11px;
      background: rgba(88,166,255,.1); color: var(--accent);
      border: 1px solid rgba(88,166,255,.2);
      font-family: var(--mono);
    }}
    .tag.tag-dim {{ background: rgba(139,148,158,.1); color: var(--muted); border-color: var(--border2); }}
    .tag.tag-ports {{ background: rgba(188,140,255,.1); color: var(--purple); border-color: rgba(188,140,255,.2); }}

    /* ── Port table ── */
    .port-table-wrap {{ overflow-x: auto; }}
    .port-table {{
      width: 100%; border-collapse: collapse;
      font-size: 13px;
    }}
    .port-table th {{
      background: rgba(22,27,34,.8);
      padding: 8px 16px;
      text-align: left;
      font-size: 11px;
      font-weight: 600;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .5px;
      border-bottom: 1px solid var(--border);
    }}
    .port-table td {{
      padding: 9px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }}
    .port-table tr:last-child td {{ border-bottom: none; }}
    .port-table tr:hover td {{ background: rgba(255,255,255,.02); }}

    .port-num {{ font-family: var(--mono); font-weight: 600; color: var(--accent); }}
    .service-name {{ font-family: var(--mono); color: var(--orange); }}
    .rtt {{ font-family: var(--mono); color: var(--muted); font-size: 12px; }}
    .banner-cell {{
      font-family: var(--mono); font-size: 11px; color: var(--muted);
      max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      cursor: default;
    }}

    .state-badge {{
      padding: 2px 8px; border-radius: 4px; font-size: 11px;
      font-weight: 600; text-transform: uppercase; letter-spacing: .4px;
      font-family: var(--mono);
    }}
    .state-badge.open {{ background: rgba(63,185,80,.15); color: var(--green); }}
    .state-badge.filtered {{ background: rgba(210,153,34,.12); color: var(--orange); }}

    .no-ports {{ padding: 16px 20px; color: var(--muted); font-size: 13px; }}

    /* ── Footer ── */
    .footer {{
      margin: 32px 32px 0;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      display: flex; justify-content: space-between;
    }}

    @media (max-width: 640px) {{
      .stats-bar {{ flex-wrap: wrap; }}
      .stat-item {{ flex: 1 0 45%; }}
      .hosts-container, .scan-meta, .footer {{ padding-left: 16px; padding-right: 16px; margin-left: 0; margin-right: 0; }}
      .top-bar {{ padding: 16px; }}
    }}
  </style>
</head>
<body>

<div class="top-bar">
  <div class="logo-mark">NS</div>
  <div>
    <h1>Net<span>Scout</span></h1>
    <div class="subtitle">Network Reconnaissance Tool — Scan Report</div>
  </div>
</div>

<div class="stats-bar">
  <div class="stat-item">
    <div class="stat-label">Hosts Scanned</div>
    <div class="stat-value accent">{len(results)}</div>
  </div>
  <div class="stat-item">
    <div class="stat-label">Hosts Up</div>
    <div class="stat-value green">{up_count}</div>
  </div>
  <div class="stat-item">
    <div class="stat-label">Open Ports</div>
    <div class="stat-value orange">{total_open}</div>
  </div>
  <div class="stat-item">
    <div class="stat-label">Protocol</div>
    <div class="stat-value" style="font-size:16px">{protocol}</div>
  </div>
  <div class="stat-item">
    <div class="stat-label">Scan Time</div>
    <div class="stat-value" style="font-size:16px;color:var(--muted)">{scan_meta.get('total_time', 'N/A')}</div>
  </div>
</div>

<div class="scan-meta">
  <span class="cmd">$ {cmd}</span><br>
  <strong>Targets:</strong> {target_str} &nbsp;|&nbsp;
  <strong>Ports:</strong> {port_spec} &nbsp;|&nbsp;
  <strong>Generated:</strong> {ts}
</div>

<div class="hosts-container">
  {host_cards}
</div>

<div class="footer">
  <span>NetScout v1.0 — Educational Network Scanner</span>
  <span>Generated {ts}</span>
</div>

</body>
</html>"""


def save_report(content: str, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
