"""
NetScout PRO — HTML Report Generator (v2)
Produces a full self-contained dark-theme pentest report with:
- Executive summary with risk gauge
- Per-host findings table with CVE links
- Vulnerability breakdown by severity
- Scan metadata
"""

from typing import List
from core.scanner import HostResult, PortState
from core.vulndb import VULNDB, findings_for_host


def to_html_pro(results: List[HostResult], scan_meta: dict) -> str:
    up_hosts = [h for h in results if h.is_up]
    total_open = sum(len(h.ports) for h in up_hosts)
    all_findings = []
    for h in up_hosts:
        for p, v in findings_for_host(h.ports):
            all_findings.append((h, p, v))
    crit = sum(1 for _, _, v in all_findings if v.severity == "CRIT")
    high = sum(1 for _, _, v in all_findings if v.severity == "HIGH")
    med  = sum(1 for _, _, v in all_findings if v.severity == "MED")
    low  = sum(1 for _, _, v in all_findings if v.severity == "LOW")
    avg_risk = round(sum(getattr(h,"risk_score",0) for h in up_hosts)/max(len(up_hosts),1),1)

    def badge(sev):
        colors={"CRIT":"#FF4757","HIGH":"#F0C040","MED":"#A78BFA","LOW":"#00BEFF"}
        return f'<span style="padding:2px 7px;border-radius:3px;background:{colors.get(sev,"#5A7A9A")}22;color:{colors.get(sev,"#5A7A9A")};border:1px solid {colors.get(sev,"#5A7A9A")}44;font-size:11px;font-weight:600">{sev}</span>'

    host_rows = ""
    for h in results:
        rs = getattr(h,"risk_score",0.0)
        rl = getattr(h,"risk_level","NONE")
        vuln_count = len([p for p in h.ports if p.port in VULNDB])
        status_color = "#39D353" if h.is_up else "#5A7A9A"
        host_rows += f"""
<tr>
<td style="font-family:monospace;color:#00BEFF;font-weight:600">{h.ip}</td>
<td style="font-size:12px;color:#5A7A9A">{h.hostname or "—"}</td>
<td><span style="color:{status_color};font-weight:600">{"UP" if h.is_up else "DOWN"}</span></td>
<td style="font-size:12px">{h.os_guess or "—"}</td>
<td style="font-family:monospace;color:#00BEFF">{len(h.ports)}</td>
<td>{"—" if not h.is_up else badge(rl) if rl != "NONE" else "<span style='color:#5A7A9A'>—</span>"}</td>
<td style="font-family:monospace;color:{'#FF4757' if rs>=7 else '#F0C040' if rs>=4 else '#5A7A9A'}">{f"{rs}/10" if h.is_up else "—"}</td>
<td style="color:#F0C040">{vuln_count or "—"}</td>
</tr>"""

    finding_rows = ""
    for h, p, v in sorted(all_findings, key=lambda x: ["CRIT","HIGH","MED","LOW"].index(x[2].severity)):
        cves = ", ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{c}" style="color:#FF4757">{c}</a>' for c in v.cves)
        finding_rows += f"""
<tr>
<td>{badge(v.severity)}</td>
<td style="font-family:monospace;color:#00BEFF">{h.ip}</td>
<td style="font-family:monospace;color:#F0C040">{p.port}/{p.service}</td>
<td style="font-size:12px;max-width:240px">{v.title}</td>
<td style="font-size:11px">{cves}</td>
<td style="font-size:11px;color:#39D353;max-width:200px">{v.recommendation}</td>
</tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScout PRO Report — {scan_meta.get("targets","")}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#05090D;color:#D4E5F5;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.6;padding:0 0 60px}}
.topbar{{background:#0C1219;border-bottom:1px solid #1A2738;padding:16px 32px;display:flex;align-items:center;gap:14px}}
.logo{{font-size:18px;font-weight:600;color:#00BEFF;letter-spacing:-.5px}}
.logo-box{{width:28px;height:28px;border:1.5px solid #00BEFF;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:11px}}
.pro-tag{{background:#00BEFF22;color:#00BEFF;border:1px solid #003D5A;border-radius:3px;padding:2px 7px;font-size:10px;letter-spacing:.5px}}
.container{{max-width:1100px;margin:0 auto;padding:28px 32px 0}}
.section{{margin-bottom:32px}}
.section-title{{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#5A7A9A;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #1A2738}}
.summary-grid{{display:grid;grid-template-columns:repeat(7,1fr);gap:10px;margin-bottom:28px}}
.sum-card{{background:#0C1219;border:1px solid #1A2738;border-radius:6px;padding:12px 14px}}
.sum-label{{font-size:9px;letter-spacing:.8px;text-transform:uppercase;color:#3A5070;margin-bottom:4px}}
.sum-val{{font-size:22px;font-weight:600}}
table{{width:100%;border-collapse:collapse;background:#090E14;border:1px solid #1A2738;border-radius:6px;overflow:hidden}}
th{{background:#0C1219;padding:8px 14px;text-align:left;font-size:10px;font-weight:500;color:#5A7A9A;letter-spacing:.8px;text-transform:uppercase;border-bottom:1px solid #1A2738}}
td{{padding:8px 14px;border-bottom:1px solid #0F1822;font-size:12px;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#0D1520}}
.meta-box{{background:#090E14;border:1px solid #1A2738;border-radius:6px;padding:14px 18px;font-size:11px;color:#5A7A9A;line-height:2}}
.meta-box strong{{color:#8AABCC}}
.footer{{margin-top:40px;padding-top:16px;border-top:1px solid #1A2738;font-size:11px;color:#3A5070;display:flex;justify-content:space-between}}
a{{color:#00BEFF;text-decoration:none}}
a:hover{{text-decoration:underline}}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo-box">NS</div>
  <div class="logo">NetScout <span style="font-weight:400;color:#5A7A9A">PRO</span></div>
  <div class="pro-tag">PENTEST REPORT v2.0</div>
  <div style="margin-left:auto;font-size:11px;color:#5A7A9A">{scan_meta.get("timestamp","")}</div>
</div>
<div class="container">

<div class="section">
<div class="section-title">Executive Summary</div>
<div class="summary-grid">
<div class="sum-card"><div class="sum-label">Hosts Scanned</div><div class="sum-val" style="color:#00BEFF">{len(results)}</div></div>
<div class="sum-card"><div class="sum-label">Hosts Up</div><div class="sum-val" style="color:#39D353">{len(up_hosts)}</div></div>
<div class="sum-card"><div class="sum-label">Open Ports</div><div class="sum-val" style="color:#F0C040">{total_open}</div></div>
<div class="sum-card"><div class="sum-label">Critical</div><div class="sum-val" style="color:#FF4757">{crit}</div></div>
<div class="sum-card"><div class="sum-label">High</div><div class="sum-val" style="color:#F0C040">{high}</div></div>
<div class="sum-card"><div class="sum-label">Med/Low</div><div class="sum-val" style="color:#A78BFA">{med+low}</div></div>
<div class="sum-card"><div class="sum-label">Avg Risk</div><div class="sum-val" style="color:#{'FF4757' if avg_risk>=7 else 'F0C040' if avg_risk>=4 else '5A7A9A'}">{avg_risk}/10</div></div>
</div>
<div class="meta-box">
<strong>Command:</strong> {scan_meta.get("command","netscout")} &nbsp;|&nbsp;
<strong>Target:</strong> {scan_meta.get("targets","")} &nbsp;|&nbsp;
<strong>Ports:</strong> {scan_meta.get("port_spec","")} &nbsp;|&nbsp;
<strong>Protocol:</strong> {scan_meta.get("protocol","tcp").upper()} &nbsp;|&nbsp;
<strong>Duration:</strong> {scan_meta.get("total_time","?")}
</div>
</div>

<div class="section">
<div class="section-title">Host Summary</div>
<table><thead><tr><th>IP</th><th>Hostname</th><th>Status</th><th>OS</th><th>Open Ports</th><th>Risk Level</th><th>Risk Score</th><th>Vulns</th></tr></thead>
<tbody>{host_rows}</tbody></table>
</div>

{'<div class="section"><div class="section-title">Vulnerability Findings</div><table><thead><tr><th>Severity</th><th>Host</th><th>Port/Service</th><th>Vulnerability</th><th>CVEs</th><th>Recommendation</th></tr></thead><tbody>'+finding_rows+'</tbody></table></div>' if finding_rows else ''}

<div class="footer">
<span>NetScout PRO v2.0 — For authorized security testing only</span>
<span>Generated {scan_meta.get("timestamp","")}</span>
</div>

</div>
</body>
</html>"""
