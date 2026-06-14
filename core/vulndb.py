"""
NetScout PRO — Vulnerability & Risk Database
CVE-correlated knowledge base for common services.
Built-in CVE knowledge base — automatic vulnerability correlation per open port.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class VulnEntry:
    port: int
    service: str
    severity: str          # CRIT / HIGH / MED / LOW
    cves: List[str]
    title: str
    description: str
    recommendation: str
    cvss_score: float      # 0.0 – 10.0
    affected_versions: str = ""
    references: List[str] = field(default_factory=list)


# ── Severity → base risk weight ───────────────────────────────────────────────
SEV_WEIGHT = {"CRIT": 9.0, "HIGH": 6.5, "MED": 3.5, "LOW": 1.0}


# ── The database ──────────────────────────────────────────────────────────────
VULNDB: Dict[int, VulnEntry] = {

    21: VulnEntry(21, "ftp", "CRIT",
        ["CVE-2011-2523"],
        "vsftpd 2.3.4 Backdoor",
        "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200 "
        "when a username containing ':)' is supplied. Trivially exploitable.",
        "Upgrade vsftpd to ≥3.0.5. Disable anonymous FTP. Prefer SFTP over FTP.",
        9.8, "vsftpd 2.3.4",
        ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
         "https://www.exploit-db.com/exploits/17491"]),

    22: VulnEntry(22, "ssh", "MED",
        ["CVE-2023-38408", "CVE-2023-51385"],
        "OpenSSH Agent Forwarding / ProxyCommand Injection",
        "OpenSSH <9.6p1 allows code injection via hostname patterns in "
        "ssh_config when combined with agent forwarding. CVE-2023-51385 adds "
        "shell metacharacter injection via crafted hostnames.",
        "Upgrade OpenSSH to ≥9.6p1. Disable agent forwarding in ssh_config. "
        "Use ssh-agent only when required.",
        6.5, "OpenSSH < 9.6p1",
        ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
         "https://nvd.nist.gov/vuln/detail/CVE-2023-51385"]),

    23: VulnEntry(23, "telnet", "CRIT",
        ["CVE-1999-0619"],
        "Telnet Plaintext Credential Exposure",
        "Telnet transmits all data including credentials in cleartext. "
        "Trivially intercepted on any shared or switched network via ARP "
        "spoofing. No encryption, no integrity protection.",
        "Disable Telnet service immediately. Replace with SSH. "
        "If legacy hardware requires Telnet, isolate on dedicated VLAN.",
        9.1, "All versions",
        ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0619"]),

    25: VulnEntry(25, "smtp", "MED",
        ["CVE-2020-7247"],
        "OpenSMTPD Remote Code Execution",
        "OpenSMTPD ≤6.6.1p1 allows remote unauthenticated attackers to "
        "execute arbitrary commands as root via a crafted SMTP session. "
        "Also check for open relay configuration.",
        "Upgrade OpenSMTPD. Restrict SMTP to authenticated users only. "
        "Test for open relay with MX Toolbox.",
        9.8, "OpenSMTPD ≤ 6.6.1p1",
        ["https://nvd.nist.gov/vuln/detail/CVE-2020-7247"]),

    80: VulnEntry(80, "http", "CRIT",
        ["CVE-2021-41773", "CVE-2021-42013"],
        "Apache 2.4.49/50 Path Traversal & RCE",
        "Apache HTTP Server 2.4.49 allows path traversal outside document "
        "root via URL-encoded sequences. If mod_cgi is enabled, remote code "
        "execution is achievable without authentication.",
        "Update Apache to ≥2.4.51 immediately. Disable mod_cgi where not "
        "required. Ensure 'Require all denied' is set for filesystem roots.",
        9.8, "Apache 2.4.49 – 2.4.50",
        ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
         "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"]),

    110: VulnEntry(110, "pop3", "LOW",
        ["CVE-2007-1711"],
        "POP3 Cleartext Authentication",
        "POP3 without STARTTLS or POP3S transmits usernames and passwords "
        "in cleartext. Susceptible to credential harvesting on local networks.",
        "Disable POP3 on port 110. Use POP3S (995) with TLS. "
        "Prefer IMAPS (993) for modern mail clients.",
        4.3, "All plain POP3 servers"),

    139: VulnEntry(139, "netbios-ssn", "HIGH",
        ["CVE-2017-0143", "CVE-2017-0144"],
        "EternalBlue / MS17-010 SMBv1 RCE",
        "Windows SMBv1 on port 139/445 is vulnerable to EternalBlue, "
        "the exploit used by WannaCry and NotPetya ransomware. "
        "Unauthenticated remote code execution as SYSTEM.",
        "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
        "Apply MS17-010. Block 139/445 at perimeter.",
        9.3, "Windows XP – Server 2008 R2 unpatched",
        ["https://nvd.nist.gov/vuln/detail/CVE-2017-0143"]),

    161: VulnEntry(161, "snmp", "MED",
        ["CVE-2002-0013", "CVE-2017-6736"],
        "SNMPv1/v2c Community String Brute-force",
        "SNMP with default community strings ('public', 'private') exposes "
        "full network topology, routing tables, and interface information. "
        "SNMPv1/v2c uses no encryption. CVE-2017-6736 adds IOS RCE via SNMP.",
        "Migrate to SNMPv3 with authPriv security. Change all community "
        "strings. Restrict SNMP to management VLAN only.",
        7.5, "SNMPv1 / SNMPv2c (all)",
        ["https://nvd.nist.gov/vuln/detail/CVE-2002-0013"]),

    443: VulnEntry(443, "https", "LOW",
        ["CVE-2014-0160"],
        "Heartbleed OpenSSL Memory Disclosure",
        "OpenSSL 1.0.1 through 1.0.1f leaks up to 64KB of server memory "
        "per request, potentially exposing private keys, session tokens, "
        "and plaintext credentials.",
        "Upgrade OpenSSL to ≥1.0.1g. Revoke and reissue all TLS certificates. "
        "Rotate all session secrets and passwords.",
        7.5, "OpenSSL 1.0.1 – 1.0.1f",
        ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
         "https://heartbleed.com"]),

    445: VulnEntry(445, "microsoft-ds", "CRIT",
        ["CVE-2017-0144", "CVE-2020-0796"],
        "EternalBlue SMBv1 + SMBGhost (CoronaBlue)",
        "Port 445 carries both EternalBlue (SMBv1) and SMBGhost "
        "(CVE-2020-0796, SMBv3.1.1 compression integer overflow). "
        "Both allow pre-auth wormable remote code execution.",
        "Disable SMBv1. Patch CVE-2020-0796 (KB4551762). "
        "Block port 445 at all perimeter firewalls.",
        9.8, "Windows 7 – Server 2008 R2 (EternalBlue); Windows 10 1903/1909 (SMBGhost)",
        ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
         "https://nvd.nist.gov/vuln/detail/CVE-2020-0796"]),

    1433: VulnEntry(1433, "mssql", "HIGH",
        ["CVE-2014-4080", "CVE-2019-1064"],
        "MSSQL Exposed Without Authentication Hardening",
        "Microsoft SQL Server exposed on 1433 is a common lateral movement "
        "target. CVE-2019-1064 allows privilege escalation. Default sa "
        "account with weak password gives xp_cmdshell OS access.",
        "Disable xp_cmdshell. Rename sa account. Use Windows Authentication. "
        "Firewall port 1433 to application servers only.",
        8.8, "MSSQL 2012–2019",
        ["https://nvd.nist.gov/vuln/detail/CVE-2014-4080"]),

    2375: VulnEntry(2375, "docker", "CRIT",
        ["CVE-2019-5736", "CVE-2019-14271"],
        "Docker Daemon Exposed Without TLS — Full Host Compromise",
        "Docker API on port 2375 without TLS allows any client to create "
        "privileged containers, mount the host filesystem, and achieve "
        "complete host compromise with a single API call.",
        "Never expose Docker API without mTLS. Use unix socket "
        "(unix:///var/run/docker.sock). Enable Docker Content Trust.",
        9.8, "Docker < 18.09.2",
        ["https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
         "https://docs.docker.com/engine/security/protect-access/"]),

    3306: VulnEntry(3306, "mysql", "HIGH",
        ["CVE-2012-2122", "CVE-2016-6662"],
        "MySQL Authentication Bypass + Arbitrary File Read",
        "CVE-2012-2122: timing attack allows login bypass in MySQL <5.5.62. "
        "CVE-2016-6662: authenticated users can inject malicious config "
        "via mysqldump, leading to RCE as mysql user.",
        "Upgrade MySQL. Restrict bind-address to 127.0.0.1 or application "
        "server IP. Disable FILE privilege. Use strong passwords.",
        9.0, "MySQL < 5.5.62 / MariaDB < 10.1.26",
        ["https://nvd.nist.gov/vuln/detail/CVE-2012-2122",
         "https://nvd.nist.gov/vuln/detail/CVE-2016-6662"]),

    3389: VulnEntry(3389, "rdp", "CRIT",
        ["CVE-2019-0708", "CVE-2019-1181"],
        "BlueKeep + DejaBlue — Pre-Auth Wormable RDP RCE",
        "CVE-2019-0708 (BlueKeep): pre-authentication RCE in RDP affecting "
        "Windows 7/XP/Server 2008. Wormable — no user interaction required. "
        "CVE-2019-1181/1182 (DejaBlue) extends this to Windows 10.",
        "Apply MS19-0708 patch immediately. Enable NLA (Network Level "
        "Authentication). Block 3389 at perimeter. Use VPN for RDP access.",
        9.8, "Windows XP – Windows 10 (unpatched)",
        ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
         "https://nvd.nist.gov/vuln/detail/CVE-2019-1181"]),

    5432: VulnEntry(5432, "postgresql", "HIGH",
        ["CVE-2019-9193", "CVE-2023-2454"],
        "PostgreSQL COPY TO/FROM PROGRAM — RCE",
        "PostgreSQL superuser can execute arbitrary OS commands via "
        "COPY TO/FROM PROGRAM. CVE-2023-2454 adds schema confusion "
        "allowing privilege escalation from unprivileged roles.",
        "Revoke SUPERUSER from application accounts. Use pg_hba.conf "
        "to restrict connections. Upgrade to ≥15.3.",
        8.8, "PostgreSQL < 15.3",
        ["https://nvd.nist.gov/vuln/detail/CVE-2019-9193"]),

    5900: VulnEntry(5900, "vnc", "HIGH",
        ["CVE-2006-2369", "CVE-2023-29320"],
        "VNC NullAuth / Authentication Bypass",
        "Some VNC servers allow NullAuthentication — connecting without "
        "any password. RealVNC <6.11.0 has further authentication bypass "
        "vulnerabilities. Full GUI access to the target desktop.",
        "Disable NullAuth. Set strong VNC password. Tunnel VNC over SSH. "
        "Consider replacing with a modern remote desktop solution.",
        9.8, "Various VNC servers",
        ["https://nvd.nist.gov/vuln/detail/CVE-2006-2369"]),

    6379: VulnEntry(6379, "redis", "HIGH",
        ["CVE-2022-0543", "CVE-2023-41056"],
        "Redis Lua Sandbox Escape + Remote Code Execution",
        "CVE-2022-0543: Debian/Ubuntu Redis packages contain a Lua sandbox "
        "escape allowing arbitrary code execution. Redis without auth "
        "also allows CONFIG SET to write cron jobs / SSH keys to disk.",
        "Bind to 127.0.0.1. Set requirepass with strong password. "
        "Enable protected-mode. Upgrade to ≥7.0.8.",
        9.8, "Redis < 7.0.8 (Debian/Ubuntu builds)",
        ["https://nvd.nist.gov/vuln/detail/CVE-2022-0543"]),

    8080: VulnEntry(8080, "http-alt", "HIGH",
        ["CVE-2019-0232", "CVE-2020-1938"],
        "Apache Tomcat CGI RCE + Ghostcat AJP LFI",
        "CVE-2019-0232: Tomcat CGI enablecmdLineArguments on Windows allows "
        "RCE via crafted query strings. CVE-2020-1938 (Ghostcat): AJP "
        "connector allows file inclusion and RCE in all Tomcat versions.",
        "Upgrade Tomcat to ≥9.0.31. Disable AJP connector if unused. "
        "Set enablecmdLineArguments=false on all CGI servlets.",
        9.8, "Tomcat < 9.0.31",
        ["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"]),

    9200: VulnEntry(9200, "elasticsearch", "CRIT",
        ["CVE-2014-3120", "CVE-2015-1427"],
        "Elasticsearch Unauthenticated Access + Dynamic Scripting RCE",
        "Elasticsearch <5.0 exposes all indices without authentication by "
        "default. CVE-2015-1427 (Groovy sandbox escape) allows RCE via "
        "crafted search queries. Countless data breaches resulted.",
        "Enable X-Pack security / OpenSearch Security plugin. "
        "Bind to localhost. Never expose 9200/9300 to the internet.",
        9.8, "Elasticsearch < 5.0",
        ["https://nvd.nist.gov/vuln/detail/CVE-2015-1427"]),

    10250: VulnEntry(10250, "kubelet", "CRIT",
        ["CVE-2018-1002105", "CVE-2019-11246"],
        "Kubernetes kubelet API Unauthenticated Access",
        "kubelet port 10250 with anonymous auth enabled allows remote "
        "command execution in any pod. CVE-2018-1002105 allows privilege "
        "escalation to cluster-admin via API server proxy.",
        "Disable anonymous kubelet auth. Use RBAC. Restrict 10250 to "
        "control plane only. Enable kubelet TLS.",
        9.8, "Kubernetes < 1.13.4",
        ["https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"]),

    11211: VulnEntry(11211, "memcached", "HIGH",
        ["CVE-2016-8704", "CVE-2018-1000115"],
        "Memcached Binary Protocol Heap Overflow + DDoS Amplification",
        "CVE-2016-8704: heap overflow in memcached binary protocol. "
        "CVE-2018-1000115: memcached UDP port 11211 used in record-setting "
        "51,000x amplification DDoS attacks (GitHub 2018: 1.3Tbps).",
        "Bind to 127.0.0.1 only. Disable UDP. Upgrade to ≥1.5.6. "
        "Block 11211 at all public-facing firewalls.",
        9.8, "Memcached < 1.5.6",
        ["https://nvd.nist.gov/vuln/detail/CVE-2016-8704"]),

    15672: VulnEntry(15672, "rabbitmq-mgmt", "HIGH",
        ["CVE-2021-32718", "CVE-2021-32719"],
        "RabbitMQ Management UI Default Credentials + XSS",
        "RabbitMQ management console default credentials (guest/guest) "
        "allow full broker control. CVE-2021-32718/32719 add stored XSS "
        "in queue and virtual host names.",
        "Change default guest credentials immediately. Restrict management "
        "plugin to localhost. Upgrade to ≥3.8.18.",
        8.8, "RabbitMQ < 3.8.18",
        ["https://nvd.nist.gov/vuln/detail/CVE-2021-32718"]),

    27017: VulnEntry(27017, "mongodb", "CRIT",
        ["CVE-2019-2386", "CVE-2021-20328"],
        "MongoDB Unauthenticated Access — Full Data Exposure",
        "MongoDB without --auth enabled exposes all databases without "
        "credentials. Millions of MongoDB instances were wiped and "
        "ransomed in 2017. CVE-2021-20328 adds client-side field "
        "level encryption bypass.",
        "Enable --auth at startup. Bind to 127.0.0.1. Use TLS. "
        "Upgrade to ≥5.0. Never expose 27017 to the internet.",
        9.8, "MongoDB < 4.4 (without auth)",
        ["https://nvd.nist.gov/vuln/detail/CVE-2019-2386"]),
}


def score_host(open_ports: list) -> tuple[float, str]:
    """
    Calculate a risk score (0.0–10.0) and level for a host
    based on its open ports against the vuln database.
    Returns (score, level) where level is CRIT/HIGH/MED/LOW/NONE.
    """
    if not open_ports:
        return 0.0, "NONE"

    total = 0.0
    hits = 0
    for p in open_ports:
        entry = VULNDB.get(p.port)
        if entry:
            total += SEV_WEIGHT[entry.severity]
            hits += 1

    if hits == 0:
        return 0.0, "NONE"

    # Normalise: average severity weighted by hit density
    density = hits / max(len(open_ports), 1)
    raw = (total / hits) * (0.7 + 0.3 * density)
    score = round(min(10.0, raw), 1)

    if score >= 8.0:
        level = "CRIT"
    elif score >= 5.5:
        level = "HIGH"
    elif score >= 3.0:
        level = "MED"
    else:
        level = "LOW"

    return score, level


def findings_for_host(open_ports: list) -> list:
    """Return list of VulnEntry objects for ports with known vulnerabilities."""
    results = []
    for p in open_ports:
        entry = VULNDB.get(p.port)
        if entry:
            results.append((p, entry))
    results.sort(key=lambda x: SEV_WEIGHT[x[1].severity], reverse=True)
    return results
